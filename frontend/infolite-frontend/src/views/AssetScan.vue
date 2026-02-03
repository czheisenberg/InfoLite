<template>
  <div class="asset-scan-page">
    <!-- 页面头部 -->
    <div class="page-header">
      <h1 class="page-title">InfoLite 网络资产扫描平台</h1>
      <!-- <p class="page-desc">支持IP端口探测、组件指纹识别，首次扫描自动入库，二次查询秒返回</p> -->

      <el-button 
        icon="Moon" 
        circle 
        size="large" 
        class="theme-toggle-btn"
        @click="toggleTheme"
        :icon="theme === 'light' ? 'Moon' : 'Sunny'"
        title="切换主题"
      />
    </div>

    <!-- 扫描表单 -->
    <div class="scan-form-card">
      <el-card shadow="hover" border>
        <el-form :model="scanForm" inline @submit.prevent="handleQuery">
          <el-form-item label="目标IP" prop="ip">
            <el-input
              v-model="scanForm.ip"
              placeholder="请输入要扫描的IP（如127.0.0.1）"
              clearable
              style="width: 300px"
              @keyup.enter="handleQuery"
            />
          </el-form-item>
          <el-form-item>
            <el-button type="primary" icon="Search" @click="handleQuery">
              查询/扫描
            </el-button>
            <el-button type="success" icon="Refresh" @click="handleRefresh" :disabled="!scanForm.ip">
              刷新扫描
            </el-button>
          </el-form-item>
        </el-form>
      </el-card>
    </div>

    <!-- 扫描结果 -->
    <div class="scan-result-card" v-if="hasResult">
      <el-card shadow="hover" border>
        <div class="result-header">
          <h3>
            扫描结果
            <el-tag :type="scanType === 'db_query' ? 'info' : 'primary'">
              {{ scanType === 'db_query' ? '从数据库查询' : '实时扫描结果' }}
            </el-tag>
          </h3>
          <p>共检测到 {{ tableData.length }} 个开放端口/资产</p>
        </div>

        <!-- 结果表格 -->
        <el-table
          :data="tableData"
          border
          stripe
          highlight-current-row
          style="width: 100%; margin-top: 10px"
          empty-text="该IP无开放端口或扫描失败"
        >
          <el-table-column prop="ip" label="目标IP" align="center" width="120" />
          <el-table-column prop="port" label="开放端口" align="center" width="100" />
          <el-table-column prop="protocol" label="协议" align="center" width="100">
            <template #default="scope">
              <el-tag :type="scope.row.protocol === 'https' ? 'danger' : 'success'">
                {{ scope.row.protocol }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="status" label="端口状态" align="center" width="100">
            <template #default="scope">
              <el-tag type="success">{{ scope.row.status }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="banner" label="Banner" align="center" width="100" />
          <el-table-column prop="fingerprint" label="组件指纹" align="center">
            <template #default="scope">
              <span v-if="scope.row.fingerprint.length > 0">
                {{ scope.row.fingerprint.join('、') }}
              </span>
              <span v-else style="color: #999">未识别</span>
            </template>
          </el-table-column>
          <el-table-column prop="scan_time_str" label="扫描时间" align="center" width="180" />
          <el-table-column label="操作" align="center" width="120">
            <template #default="scope">
              <el-button
                type="text"
                icon="InfoFilled"
                @click="showDetail(scope.row)"
                title="查看详情"
              >
                详情
              </el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-card>
    </div>

    <!-- 资产详情弹窗 -->
    <el-dialog
      title="资产详情"
      v-model="detailDialogVisible"
      width="60%"
      center
      destroy-on-close
    >
      <el-descriptions :column="1" border :data="currentAsset" v-if="currentAsset">
        <el-descriptions-item label="目标IP">{{ currentAsset.ip }}</el-descriptions-item>
        <el-descriptions-item label="开放端口">{{ currentAsset.port }}</el-descriptions-item>
        <el-descriptions-item label="协议">{{ currentAsset.protocol }}</el-descriptions-item>
        <el-descriptions-item label="端口状态">{{ currentAsset.status }}</el-descriptions-item>
        <el-descriptions-item label="服务Banner">{{ currentAsset.banner || '未知' }}</el-descriptions-item>
        <el-descriptions-item label="组件指纹">
          {{ currentAsset.fingerprint.length > 0 ? currentAsset.fingerprint.join('、') : '未识别' }}
        </el-descriptions-item>
        <el-descriptions-item label="HTTP状态码" v-if="currentAsset.http_info">
          {{ currentAsset.http_info.status_code }}
        </el-descriptions-item>
        <el-descriptions-item label="扫描时间">{{ currentAsset.scan_time_str }}</el-descriptions-item>
      </el-descriptions>
      <template #footer>
        <el-button @click="detailDialogVisible = false">关闭</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, reactive, computed } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
// 引入封装的axios请求
import request from '../utils/request'

// 主题
import { inject } from 'vue'
const theme = inject('theme')
const toggleTheme = inject('toggleTheme')

// 扫描表单数据
const scanForm = reactive({
  ip: '' // 目标IP
})

// 表格数据（扫描结果）
const tableData = ref([])
// 扫描类型（db_query:数据库查询，scan:实时扫描）
const scanType = ref('')
// 是否有结果（控制结果区域显示）
const hasResult = computed(() => tableData.value.length > 0)
// 详情弹窗
const detailDialogVisible = ref(false)
// 当前选中的资产
const currentAsset = ref({})

// IP格式校验
const validateIp = (ip) => {
  const reg = /^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$/
  return reg.test(ip)
}

// 处理查询/扫描（默认不刷新）
const handleQuery = async () => {
  // IP校验
  if (!scanForm.ip) {
    ElMessage.warning('请输入目标IP地址')
    return
  }
  if (!validateIp(scanForm.ip)) {
    ElMessage.error('请输入正确的IP地址（如127.0.0.1）')
    return
  }

  try {
    // 调用后端接口，refresh=false（默认不刷新）
    const res = await request.get('/asset/query', {
      params: { ip: scanForm.ip, refresh: false }
    })
    tableData.value = res.data
    scanType.value = res.scan_type
    // 提示成功
    ElMessage.success(res.msg)
  } catch (error) {
    console.error('查询失败：', error)
    tableData.value = []
  }
}

// 处理刷新扫描（强制重新扫描）
const handleRefresh = async () => {
  try {
    ElMessageBox.confirm(
      '确定要刷新扫描该IP吗？会重新执行端口探测并覆盖旧数据',
      '提示',
      {
        confirmButtonText: '确定',
        cancelButtonText: '取消',
        type: 'warning'
      }
    ).then(async () => {
      // 调用后端接口，refresh=true（强制刷新）
      const res = await request.get('/asset/query', {
        params: { ip: scanForm.ip, refresh: true }
      })
      tableData.value = res.data
      scanType.value = res.scan_type
      ElMessage.success(res.msg)
    })
  } catch (error) {
    console.error('刷新扫描失败：', error)
    ElMessage.info('已取消刷新扫描')
  }
}

// 查看资产详情
const showDetail = (row) => {
  currentAsset.value = row
  detailDialogVisible.value = true
}
</script>

<style scoped>
/* 页面整体样式：替换为CSS变量 👇 */
.asset-scan-page {
  max-width: 1400px;
  margin: 0 auto;
  padding: 20px;
  background-color: var(--bg-main);
  min-height: 100vh;
}

/* 页面头部：新增flex布局，容纳切换按钮 */
.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  text-align: left;
  margin-bottom: 30px;
  padding-bottom: 15px;
  border-bottom: 1px solid var(--border-color);
}
.header-left {
  flex: 1;
}
.page-title {
  font-size: 28px;
  color: var(--text-primary);
  margin: 0 0 10px 0;
  font-weight: 600;
}
.page-desc {
  font-size: 16px;
  color: var(--text-secondary);
  margin: 0;
}
/* 主题切换按钮样式 */
.theme-toggle-btn {
  margin-left: 20px;
  --el-button-bg-color: var(--bg-card);
  --el-button-text-color: var(--text-primary);
  --el-button-hover-bg-color: var(--hover-color);
}

/* 扫描表单 */
.scan-form-card {
  margin-bottom: 30px;
}

/* 扫描结果 */
.scan-result-card {
  margin-top: 20px;
}
.result-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 10px;
}
.result-header h3 {
  font-size: 18px;
  color: var(--text-primary);
  margin: 0;
  display: flex;
  align-items: center;
  gap: 10px;
}
.result-header p {
  font-size: 14px;
  color: var(--text-secondary);
  margin: 0;
}

/* 响应式适配 */
@media (max-width: 768px) {
  .asset-scan-page {
    padding: 10px;
  }
  .page-title {
    font-size: 24px;
  }
  .el-input {
    width: 200px !important;
  }
  .result-header {
    flex-direction: column;
    align-items: flex-start;
    gap: 5px;
  }
  .page-header {
    flex-direction: column;
    align-items: flex-start;
    gap: 15px;
    text-align: left;
  }
  .theme-toggle-btn {
    align-self: flex-end;
    margin-left: 0;
  }
}
</style>