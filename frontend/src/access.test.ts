import { describe, expect, it } from 'vitest';
import access from './access';

describe('平台角色入口权限', () => {
  it('管理员拥有写操作入口', () => {
    expect(
      access({ currentUser: { id: '1', username: 'admin', role: 'admin' } })
        .canAdmin,
    ).toBe(true);
  });
  it('只读用户没有管理入口', () => {
    expect(
      access({ currentUser: { id: '2', username: 'viewer', role: 'viewer' } })
        .canAdmin,
    ).toBe(false);
  });
  it('未登录没有管理入口', () => {
    expect(access(undefined).canAdmin).toBe(false);
  });
});
