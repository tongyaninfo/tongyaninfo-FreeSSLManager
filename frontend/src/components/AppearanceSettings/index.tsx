import type { SettingDrawerProps } from '@ant-design/pro-components';
import { SettingDrawer } from '@ant-design/pro-components';
import { useIntl, useModel } from '@umijs/max';
import { Space, Switch, Tooltip, Typography } from 'antd';
import React, { useEffect } from 'react';
import {
  resolveTheme,
  saveThemeMode,
  subscribeSystemTheme,
  type ThemeMode,
} from '@/utils/theme';

/** 复用原有外观设置，额外保存自动模式，避免框架把系统深浅色当作用户选择。 */
export default function AppearanceSettings() {
  const { initialState, setInitialState } = useModel('@@initialState');
  const intl = useIntl();
  const mode = initialState?.themeMode ?? 'light';
  const automatic = mode === 'auto';
  const followSystemLabel = intl.formatMessage({
    id: 'app.setting.pagestyle.auto',
    defaultMessage: '跟随系统',
  });

  useEffect(() => {
    saveThemeMode(mode);
  }, [mode]);

  useEffect(() => {
    if (!automatic) return;
    return subscribeSystemTheme((navTheme) => {
      void setInitialState((state) =>
        state?.themeMode === 'auto' && state.settings?.navTheme !== navTheme
          ? { ...state, settings: { ...state.settings, navTheme } }
          : state,
      );
    });
  }, [automatic, setInitialState]);

  const changeMode = (themeMode: ThemeMode) => {
    void setInitialState((state) => ({
      ...state,
      themeMode,
      settings: { ...state?.settings, navTheme: resolveTheme(themeMode) },
    }));
  };

  const changeSettings: SettingDrawerProps['onSettingChange'] = (settings) => {
    void setInitialState((state) => {
      const previousMode = state?.themeMode ?? 'light';
      // 原生抽屉切换混合布局时附带 navTheme=light，不能因此取消自动模式。
      const layoutChanged = settings.layout !== state?.settings?.layout;
      const themeMode =
        previousMode === 'auto' && layoutChanged
          ? 'auto'
          : (settings.navTheme ?? previousMode);
      return {
        ...state,
        themeMode,
        settings: {
          ...state?.settings,
          ...settings,
          navTheme: resolveTheme(themeMode),
        },
      };
    });
  };

  return (
    <SettingDrawer
      disableUrlParams
      enableDarkTheme
      collapse={initialState?.settingDrawerOpen}
      onCollapseChange={(settingDrawerOpen) =>
        setInitialState((state) => ({ ...state, settingDrawerOpen }))
      }
      // 自动模式不选中某个固定主题；点击任意深浅色卡片即可切回手动。
      settings={{
        ...initialState?.settings,
        navTheme: automatic ? undefined : mode,
      }}
      onSettingChange={changeSettings}
      drawerProps={{
        title: intl.formatMessage({
          id: 'globalHeader.themeSettings',
          defaultMessage: '主题设置',
        }),
        extra: (
          <Tooltip
            title={intl.formatMessage({
              id: 'app.setting.pagestyle.auto.description',
              defaultMessage: '自动模式会跟随操作系统的浅色或深色设置。',
            })}
          >
            <Space size="small">
              <Typography.Text>{followSystemLabel}</Typography.Text>
              <Switch
                aria-label={followSystemLabel}
                checked={automatic}
                onChange={(checked) =>
                  changeMode(checked ? 'auto' : resolveTheme('auto'))
                }
              />
            </Space>
          </Tooltip>
        ),
      }}
    />
  );
}
