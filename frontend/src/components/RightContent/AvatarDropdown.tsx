import { KeyOutlined, LogoutOutlined, SkinOutlined } from '@ant-design/icons';
import { history, useIntl, useModel } from '@umijs/max';
import type { MenuProps } from 'antd';
import { App, Form, Input, Modal, Spin } from 'antd';
import React, { startTransition, useState } from 'react';
import { authApi, resetCsrfToken } from '@/services/ssl-manager/api';
import HeaderDropdown from '../HeaderDropdown';

type GlobalHeaderRightProps = { children?: React.ReactNode };

export const AvatarDropdown: React.FC<GlobalHeaderRightProps> = ({
  children,
}) => {
  const { initialState, setInitialState } = useModel('@@initialState');
  const intl = useIntl();
  const { message } = App.useApp();
  const [passwordOpen, setPasswordOpen] = useState(false);
  const [passwordLoading, setPasswordLoading] = useState(false);
  const [passwordForm] = Form.useForm<{
    currentPassword: string;
    newPassword: string;
    confirmPassword: string;
  }>();
  const menuItems: MenuProps['items'] = [
    {
      key: 'changePassword',
      icon: <KeyOutlined />,
      label: intl.formatMessage({
        id: 'globalHeader.changePassword',
        defaultMessage: '修改密码',
      }),
    },
    {
      key: 'theme',
      icon: <SkinOutlined />,
      label: intl.formatMessage({
        id: 'globalHeader.themeSettings',
        defaultMessage: '主题设置',
      }),
    },
    { type: 'divider' },
    {
      key: 'logout',
      icon: <LogoutOutlined />,
      label: intl.formatMessage({
        id: 'globalHeader.logout',
        defaultMessage: '退出登录',
      }),
    },
  ];

  const onMenuClick: MenuProps['onClick'] = ({ key }) => {
    if (key === 'logout') {
      startTransition(() =>
        setInitialState((state) => ({ ...state, currentUser: undefined })),
      );
      void authApi.logout().finally(() => {
        resetCsrfToken();
        history.replace('/user/login');
      });
      return;
    }
    if (key === 'theme') {
      setInitialState((state) => ({ ...state, settingDrawerOpen: true }));
      return;
    }
    if (key === 'changePassword') {
      passwordForm.resetFields();
      setPasswordOpen(true);
    }
  };

  const changePassword = async () => {
    let values: {
      currentPassword: string;
      newPassword: string;
      confirmPassword: string;
    };
    try {
      values = await passwordForm.validateFields();
    } catch {
      // Ant Design uses a rejected promise to report field validation errors.
      // The fields already show their messages, so no global error is needed.
      return;
    }
    setPasswordLoading(true);
    try {
      const result = await authApi.changePassword({
        currentPassword: values.currentPassword,
        newPassword: values.newPassword,
      });
      if (!result.success) {
        message.error(
          result.message ||
            intl.formatMessage({
              id: 'globalHeader.changePasswordFailed',
              defaultMessage: '密码修改失败',
            }),
        );
        return;
      }
      if (result.data)
        setInitialState((state) => ({ ...state, currentUser: result.data }));
      message.success(
        intl.formatMessage({
          id: 'globalHeader.changePasswordSuccess',
          defaultMessage: '密码修改成功',
        }),
      );
      setPasswordOpen(false);
      passwordForm.resetFields();
    } finally {
      setPasswordLoading(false);
    }
  };

  if (!initialState?.currentUser) return <Spin size="small" />;
  return (
    <>
      <HeaderDropdown
        placement="bottomRight"
        menu={{ selectedKeys: [], onClick: onMenuClick, items: menuItems }}
        arrow
      >
        {children}
      </HeaderDropdown>
      <Modal
        title={intl.formatMessage({
          id: 'globalHeader.changePassword',
          defaultMessage: '修改密码',
        })}
        open={passwordOpen}
        confirmLoading={passwordLoading}
        onOk={() => void changePassword()}
        onCancel={() => {
          if (!passwordLoading) setPasswordOpen(false);
        }}
        destroyOnHidden
      >
        <Form form={passwordForm} layout="vertical" preserve={false}>
          <Form.Item
            name="currentPassword"
            label={intl.formatMessage({
              id: 'globalHeader.currentPassword',
              defaultMessage: '旧密码',
            })}
            rules={[
              {
                required: true,
                message: intl.formatMessage({
                  id: 'globalHeader.currentPasswordRequired',
                  defaultMessage: '请输入旧密码',
                }),
              },
            ]}
          >
            <Input.Password autoComplete="current-password" />
          </Form.Item>
          <Form.Item
            name="newPassword"
            label={intl.formatMessage({
              id: 'globalHeader.newPassword',
              defaultMessage: '新密码',
            })}
            rules={[
              {
                required: true,
                message: intl.formatMessage({
                  id: 'globalHeader.newPasswordRequired',
                  defaultMessage: '请输入新密码',
                }),
              },
            ]}
          >
            <Input.Password autoComplete="new-password" />
          </Form.Item>
          <Form.Item
            name="confirmPassword"
            label={intl.formatMessage({
              id: 'globalHeader.confirmPassword',
              defaultMessage: '确认新密码',
            })}
            dependencies={['newPassword']}
            rules={[
              {
                required: true,
                message: intl.formatMessage({
                  id: 'globalHeader.confirmPasswordRequired',
                  defaultMessage: '请再次输入新密码',
                }),
              },
              ({ getFieldValue }) => ({
                validator(_, value) {
                  return !value || getFieldValue('newPassword') === value
                    ? Promise.resolve()
                    : Promise.reject(
                        new Error(
                          intl.formatMessage({
                            id: 'globalHeader.passwordMismatch',
                            defaultMessage: '两次输入的密码不一致',
                          }),
                        ),
                      );
                },
              }),
            ]}
          >
            <Input.Password autoComplete="new-password" />
          </Form.Item>
        </Form>
      </Modal>
    </>
  );
};
