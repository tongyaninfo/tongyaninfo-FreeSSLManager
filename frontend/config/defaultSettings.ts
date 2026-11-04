import type { ProLayoutProps } from '@ant-design/pro-components';

const settings: ProLayoutProps & { logo?: string } = {
  navTheme: 'light',
  colorPrimary: '#1849a9',
  layout: 'mix',
  contentWidth: 'Fluid',
  fixedHeader: false,
  fixSiderbar: true,
  colorWeak: false,
  title: '通研FREE SSL管理',
  logo: '/assets/brand/tyinfo-logo-transparent.png',
  iconfontUrl: '',
  // 保留 ProLayout 的 token 通道，SettingDrawer 更新 colorPrimary/navTheme 后由 ProLayout
  // 内层 ConfigProvider 重新计算菜单和内容区域的设计令牌。
  token: {},
};

export default settings;
