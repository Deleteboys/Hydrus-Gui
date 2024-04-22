// Composables
import { createRouter, createWebHistory } from 'vue-router'
import MainPage from "../components/MainPage.vue";
// import TestPage from "@/views/TestPage.vue";

const routes = [
  {path: '/', component: MainPage},
  // {path: '/admin', component: AdminPage},
  // {path: '/admin/login', component: LoginPage}
  // {path: '/new/Test', component: TestPage},
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

export default router
