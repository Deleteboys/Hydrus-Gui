<template>
  <!--  <v-card class="fill-height">-->
  <!--    <v-card-title class="text-center" style="font-size: 2.5em; margin-top: 20px; margin-bottom: 20px">Hydrus</v-card-title>-->
  <!--    <v-card>-->
  <!--      <v-select></v-select>-->
  <!--    </v-card>-->
  <!--  </v-card>-->
  <v-container class="fill-height" fluid>
    <v-responsive class="d-flex justify-center fill-height">
      <v-card-title class="text-center text-h3" style="margin-bottom: 20px">Hydrus</v-card-title>
      <v-card class="rounded-xl" style="height: 84%" elevation="0">
        <v-card-actions>
          <v-btn-toggle style="margin: 0 auto 0 auto;" variant="outlined" color="primary" divided
                        v-model="applicationType" mandatory>
            <v-btn>Windows</v-btn>
            <v-btn>Processes</v-btn>
          </v-btn-toggle>
        </v-card-actions>
        <v-card-text class="text-center text-h6">Select a window or process:</v-card-text>
        <v-card-actions>
          <v-autocomplete class="rounded-xl" rounded variant="solo-filled" label="Process" v-model="process"
                          :items="JSON.parse(greetMsg)" item-value="process_id" item-title="name"
                          :item-props="true"></v-autocomplete>
        </v-card-actions>
        <v-card-text class="text-center text-h6">Select a DLL</v-card-text>
        <v-card-actions>
          <!--          <v-file-input class="rounded-xl" rounded variant="solo-filled" label="DLL" prepend-icon="" v-model="dll_path"></v-file-input>-->
          <v-text-field label="DLL" rounded variant="solo-filled" readonly @click="readPath"
                        v-model="dll_path"></v-text-field>
        </v-card-actions>
        <v-card-actions>
          <v-btn style="margin: 0 auto 0 auto; margin-top: 0px" variant="elevated" color="primary" class="w-50"
                 @click="inject_dll">
            Inject
          </v-btn>
        </v-card-actions>
        <v-card-actions>
          <v-btn style="margin: 0 auto 0 auto;" variant="elevated" color="primary" class="w-50"
                 @click="update_process_list">
            Refresh
          </v-btn>
        </v-card-actions>
        <!--        <v-card-text>{{ process }}</v-card-text>-->
        <!--        <v-card-text>{{ dll_path }}</v-card-text>-->
      </v-card>
    </v-responsive>
  </v-container>
</template>

<script>
import {invoke} from "@tauri-apps/api/tauri";
import {ref} from "vue";
import {open} from "@tauri-apps/api/dialog";

export default {
  name: "MainPage",
  data() {
    return {
      process: "",
      dll_path: "",
      greetMsg: "[]",
      inject_output: "",
      applicationType: 0
    }
  },
  methods: {
    async readPath() {
      const path = await open({
        multiple: false,
        filters: [{
          name: 'DLL',
          extensions: ['dll']
        }]
      })
      this.dll_path = path
    },
    async update_process_list() {
      if (this.applicationType === 0) {
        this.greetMsg = await invoke("get_all_windows");
      } else {
        this.greetMsg = await invoke("get_all_processes");
      }
    },
    async inject_dll() {
      this.inject_output = await invoke("inject_dll", {processId: this.process, dllPath: this.dll_path});
      alert(this.inject_output)
    }
  },
  mounted() {
    this.update_process_list()
  }
}
</script>

<style scoped>

</style>