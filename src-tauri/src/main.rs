// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::ffi::{CString, OsString};
use std::io::{Error, ErrorKind, stdin, stdout, Write};
use std::os::windows::ffi::OsStringExt;
use std::path::Path;
use std::process::exit;
use std::{mem, ptr};
use std::mem::size_of;
use serde::Serialize;
use serde_json::Value;
use widestring::WideCString;
use winapi::ctypes::{c_char, c_uchar};
use winapi::shared::minwindef::{BOOL, DWORD, LPARAM, MAX_PATH};
use winapi::shared::ntdef::NULL;
use winapi::shared::windef::HWND;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::CloseHandle;
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory};
use winapi::um::processthreadsapi::{CreateRemoteThread, OpenProcess};
use winapi::um::winnt::{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, PROCESS_ALL_ACCESS, PROCESS_VM_READ, PROCESS_VM_WRITE};
use winapi::um::winuser::{EnumWindows, GetWindowTextLengthA, GetWindowTextW, GetWindowThreadProcessId, IsWindowVisible};
use winapi::um::tlhelp32::{CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPMODULE, TH32CS_SNAPPROCESS};

// Learn more about Tauri commands at https://tauri.app/v1/guides/features/command
#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}


#[derive(Serialize)]
struct Process {
    name: String,
    process_id: String,
}

static mut ALL_PROCESSES: Vec<Process> = vec![];

fn enum_processes() {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPMODULE, 0);
        if !snapshot.is_null() {
            let mut proc_entry: PROCESSENTRY32 = PROCESSENTRY32 {
                dwSize: 0,
                cntUsage: 0,
                th32ProcessID: 0,
                th32DefaultHeapID: 0,
                th32ModuleID: 0,
                cntThreads: 0,
                th32ParentProcessID: 0,
                pcPriClassBase: 0,
                dwFlags: 0,
                szExeFile: [0; MAX_PATH],
            };

            proc_entry.dwSize = size_of::<PROCESSENTRY32>() as u32;
            if Process32First(snapshot, &mut proc_entry as *mut PROCESSENTRY32) != 0 {
                loop {
                    let exe_file = proc_entry.szExeFile.clone();
                    let mut exe_name = "Unkown".to_string();

                    if !exe_file.is_empty() {
                        if !exe_file.as_ptr().is_null() {
                            let exe_file = mem::transmute::<Vec<i8>,Vec<u8>>(exe_file.to_vec());
                            let length = String::from_utf8_unchecked(exe_file.clone()).find("\0").unwrap();
                            let string = String::from_utf8_unchecked(exe_file.clone()[..length].to_owned());
                            exe_name = string;
                        }
                    }

                    let process_id = format!("{:#0X}", proc_entry.th32ProcessID);
                    let name_with_id = format!("[{}] - {}", process_id, exe_name.to_string());
                    ALL_PROCESSES.push(Process {
                        process_id: process_id.to_string(),
                        name: name_with_id.to_string(),
                    });
                    if Process32Next(snapshot, &mut proc_entry as *mut PROCESSENTRY32) == 0 {
                        break;
                    }
                }
            } else {
                println!("Process32First failed: {:#x}", GetLastError());
            }
        }
    }
}

extern "system" fn enum_windows_proc(hwnd: HWND, _: LPARAM) -> BOOL {
    unsafe {
        if IsWindowVisible(hwnd) == 0 { return 1; }
        let window_text_length = GetWindowTextLengthA(hwnd);
        if window_text_length <= 0 { return 1; }

        //create buffer for the window title (max size of window title is 256 bit)
        let mut buffer = [0; 256];

        GetWindowTextW(hwnd, buffer.as_mut_ptr(), window_text_length + 1);
        let window_title = OsString::from_wide(&buffer[..window_text_length as usize]);

        //create buffer for process id as u32
        let mut buf: DWORD = 0;
        GetWindowThreadProcessId(hwnd, &mut buf);
        //format u32 to hex
        let process_id = format!("{:#0X}", buf);
        let name_with_id = format!("[{}] - {}", process_id, window_title.to_str().unwrap().to_string());

        ALL_PROCESSES.push(Process {
            process_id: process_id.to_string(),
            name: name_with_id.to_string(),
        });
        return 1;
    }
}

unsafe fn convert_all_processes_to_json() -> Result<String, Error> {
    let json_string = serde_json::to_string(&ALL_PROCESSES)?;
    Ok(json_string)
}

#[tauri::command]
fn get_all_windows() -> String {
    unsafe {
        ALL_PROCESSES = vec![];
        EnumWindows(Some(enum_windows_proc), 0);
        let output = convert_all_processes_to_json().expect("");
        output
    }
}

#[tauri::command]
fn get_all_processes() -> String {
    unsafe {
        ALL_PROCESSES = vec![];
        enum_processes();
        let output = convert_all_processes_to_json().expect("");
        output
    }
}

fn convert_hex_to_dword(input: &str) -> DWORD {
    let process_id = input;
    let remove_prefix = process_id.trim_start_matches("0x");
    let proc_id = match u32::from_str_radix(remove_prefix, 16) {
        Ok(proc_id) => proc_id,
        Err(error) => {
            println!("Could not parse the hex number {:?}", error);
            exit(1)
        }
    };
    proc_id
}

#[tauri::command]
fn inject_dll(process_id: &str, dll_path: &str) -> String {
    let dll_path = dll_path.trim();
    let dll_path = Path::new(dll_path);
    let proc_id = convert_hex_to_dword(process_id.trim());

    inject_into_process(proc_id, dll_path)
}


fn inject_into_process(proc_id: DWORD, dll: &Path) -> String {
    unsafe {
        let h_process = OpenProcess(PROCESS_ALL_ACCESS | PROCESS_VM_WRITE | PROCESS_VM_READ, 0, proc_id);
        if h_process == NULL {
            return (format!("Program could not be found the process id was {:#0X}", proc_id));
            // exit(1)
        }
        let dll_path = dll;
        let full_path = dll_path.canonicalize().expect("Error");
        let full_path = full_path.as_os_str();
        let full_path = WideCString::from_str(full_path.to_string_lossy())
            .map_err(|e| Error::new(ErrorKind::InvalidInput,
                                    format!("invalid dll path: {:?}", e))).expect("Error");

        let path_len = (full_path.len() * 2) + 1;

        let mut allocate_memory = VirtualAllocEx(h_process, ptr::null_mut(), MAX_PATH, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if allocate_memory == NULL {
            return ("Hooking the memory didn't work").to_string();
            // exit(1)
        }

        if WriteProcessMemory(h_process,
                              allocate_memory,
                              full_path.as_ptr() as *mut _,
                              path_len,
                              ptr::null_mut()) == 0 {
            let error = GetLastError();
            println!("{:?}", error);
            return ("Writing Memory went wrong").to_string();
            // exit(1)
        }
        let kernel32 = CString::new("kernel32.dll").expect("CString::new failed");
        let loadlibraryw = CString::new("LoadLibraryW").expect("CString::new failed");

        let h_kernel32 = GetModuleHandleA(kernel32.as_ptr());
        if h_kernel32.is_null() {
            return ("Failed to get the handle of kernel32.dll.").to_string();
            // exit(1);
        }
        let h_loadlibraryw =
            GetProcAddress(h_kernel32, loadlibraryw.as_ptr());
        if h_loadlibraryw.is_null() {
            return ("Failed to get the address of LoadLibraryW.").to_string();
            // exit(1)
        }
        let hthread = CreateRemoteThread(h_process, ptr::null_mut(), 0, Some(mem::transmute(h_loadlibraryw)), allocate_memory, 0, ptr::null_mut());

        CloseHandle(hthread);
        return ("Injected successfully").to_string();
    }
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![get_all_windows, inject_dll, get_all_processes])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
