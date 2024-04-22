// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::ffi::{CString, OsString};
use std::io::{Error, ErrorKind, stdin, stdout, Write};
use std::os::windows::ffi::OsStringExt;
use std::path::Path;
use std::process::exit;
use std::{mem, ptr};
use serde::Serialize;
use serde_json::Value;
use widestring::WideCString;
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

// Learn more about Tauri commands at https://tauri.app/v1/guides/features/command
#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}


#[derive(Serialize)]
struct processes {
    name: String,
    process_id: String
}

static mut ALL_PROCESSES: Vec<processes> = vec![];

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

        ALL_PROCESSES.push(processes{
            process_id: process_id.to_string(),
            name: window_title.to_str().unwrap().to_string()
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
        EnumWindows(Some(enum_windows_proc), 0);
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
fn inject_dll(process_id: &str, dll_path: &str) -> String{
    let dll_path = dll_path.trim();
    let dll_path = Path::new(dll_path);
    let proc_id = convert_hex_to_dword(process_id.trim());
    
    inject_into_process(proc_id, dll_path)
}


fn inject_into_process(proc_id: DWORD, dll: &Path) -> String{
    unsafe {
        let h_process = OpenProcess(PROCESS_ALL_ACCESS | PROCESS_VM_WRITE | PROCESS_VM_READ, 0, proc_id);
        if h_process == NULL {
            return(format!("Program could not be found the process id was {:#0X}", proc_id));
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
            return("Hooking the memory didn't work").to_string();
            // exit(1)
        }

        if WriteProcessMemory(h_process,
                              allocate_memory,
                              full_path.as_ptr() as *mut _,
                              path_len,
                              ptr::null_mut()) == 0 {
            let error = GetLastError();
            println!("{:?}", error);
            return("Writing Memory went wrong").to_string();
            // exit(1)
        }
        let kernel32 = CString::new("kernel32.dll").expect("CString::new failed");
        let loadlibraryw = CString::new("LoadLibraryW").expect("CString::new failed");

        let h_kernel32 = GetModuleHandleA(kernel32.as_ptr());
        if h_kernel32.is_null() {
            return("Failed to get the handle of kernel32.dll.").to_string();
            // exit(1);
        }
        let h_loadlibraryw =
            GetProcAddress(h_kernel32, loadlibraryw.as_ptr());
        if h_loadlibraryw.is_null() {
            return("Failed to get the address of LoadLibraryW.").to_string();
            // exit(1)
        }
        let hthread = CreateRemoteThread(h_process, ptr::null_mut(), 0, Some(mem::transmute(h_loadlibraryw)), allocate_memory, 0, ptr::null_mut());

        CloseHandle(hthread);
        return("Injected successfully").to_string()
    }
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![get_all_windows, inject_dll])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
