import { ProForm, ProFormText } from '@ant-design/pro-components';
import { history } from '@umijs/max';
import { Alert, Card } from 'antd';
import React, { useEffect, useState } from 'react';
import { authApi, resetCsrfToken } from '@/services/ssl-manager/api';

/** 首次启动创建管理员；后端完成初始化后拒绝重复创建。 */
export default function Setup() {
  const [error, setError] = useState('');
  useEffect(() => {
    authApi.setupStatus().then((result) => {
      if (result.success && !result.data?.needsSetup)
        history.replace('/user/login');
      else if (!result.success) setError(result.message);
    });
  }, []);
  return (
    <main className="ssl-auth">
      <Card title="初始化通研FREE SSL管理" className="ssl-auth-card">
        <Alert
          title="首次使用，请创建平台管理员。云平台密钥将在登录后的配置管理中录入。"
          type="info"
          showIcon
          style={{ marginBottom: 24 }}
        />
        {error && (
          <Alert
            title={error}
            type="error"
            showIcon
            style={{ marginBottom: 16 }}
          />
        )}
        <ProForm
          submitter={{
            searchConfig: { submitText: '创建管理员' },
            resetButtonProps: false,
          }}
          onFinish={async (values) => {
            if (values.password !== values.confirmPassword) {
              setError('两次输入的密码不一致');
              return false;
            }
            const { confirmPassword: _confirm, ...body } = values;
            const result = await authApi.setup(body);
            if (!result.success) {
              setError(result.message);
              return false;
            }
            resetCsrfToken();
            window.location.assign('/user/login');
            return true;
          }}
        >
          <ProFormText
            name="username"
            label="管理员用户名"
            rules={[
              { required: true, message: '请输入用户名' },
              { min: 3, message: '用户名至少 3 个字符' },
            ]}
          />
          <ProFormText name="displayName" label="显示名称" />
          <ProFormText.Password
            name="password"
            label="密码"
            fieldProps={{ autoComplete: 'new-password' }}
            rules={[
              { required: true, message: '请输入密码' },
              { min: 12, message: '密码至少 12 个字符' },
            ]}
          />
          <ProFormText.Password
            name="confirmPassword"
            label="确认密码"
            rules={[{ required: true, message: '请再次输入密码' }]}
          />
        </ProForm>
      </Card>
    </main>
  );
}
