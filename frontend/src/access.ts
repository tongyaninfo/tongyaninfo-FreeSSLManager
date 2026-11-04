import type { User } from './services/ssl-manager/types';

/** 前端控制入口可见性，后端独立校验所有写操作权限。 */
export default function access(
  initialState: { currentUser?: User } | undefined,
) {
  return { canAdmin: initialState?.currentUser?.role === 'admin' };
}
