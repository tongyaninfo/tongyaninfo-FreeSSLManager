import type { ActionType, ProTableProps } from '@ant-design/pro-components';
import { useEffect, useRef, useState } from 'react';

export type TableDensity = 'small' | 'middle' | 'large';

const densityKey = (tableKey: string) =>
  `ssl-manager:table:${tableKey}:density:v1`;

function readDensity(tableKey: string): TableDensity {
  if (typeof window === 'undefined') return 'small';
  const value = window.localStorage.getItem(densityKey(tableKey));
  return value === 'middle' || value === 'large' ? value : 'small';
}

/** 为每张 ProTable 提供独立的列显隐和密度持久化配置。 */
export function useTablePreferences(tableKey: string) {
  const [density, setDensity] = useState<TableDensity>(() =>
    readDensity(tableKey),
  );
  const onSizeChange = (value: TableDensity | undefined) => {
    const next = value ?? 'small';
    setDensity(next);
    if (typeof window !== 'undefined')
      window.localStorage.setItem(densityKey(tableKey), next);
  };
  const props: Pick<
    ProTableProps<any, any>,
    'defaultSize' | 'onSizeChange' | 'columnsState' | 'options'
  > = {
    defaultSize: density,
    onSizeChange,
    columnsState: {
      persistenceKey: `ssl-manager:table:${tableKey}:columns:v1`,
      persistenceType: 'localStorage',
    },
    options: { density: true, setting: true, reload: true },
  };
  return { density, ...props };
}

type PageState = { current: number; pageSize: number; total: number };

/** 列表默认支持左右方向键翻页，输入控件和弹窗内不拦截按键。 */
export function useTableKeyboardPagination(
  actionRef: React.MutableRefObject<ActionType | null>,
  pageState: React.MutableRefObject<PageState>,
) {
  const latestRef = useRef(pageState);
  latestRef.current = pageState;
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null;
      if (
        target?.closest(
          'input, textarea, select, [contenteditable="true"], .ant-select, .ant-picker',
        ) ||
        (() => {
          const modal = document.querySelector('.ant-modal-wrap');
          return modal && getComputedStyle(modal).display !== 'none';
        })()
      )
        return;
      if (event.key !== 'ArrowLeft' && event.key !== 'ArrowRight') return;
      const state = latestRef.current.current;
      const maxPage = Math.max(
        1,
        Math.ceil(state.total / Math.max(1, state.pageSize)),
      );
      const next =
        event.key === 'ArrowLeft' ? state.current - 1 : state.current + 1;
      if (next < 1 || next > maxPage) return;
      event.preventDefault();
      actionRef.current?.setPageInfo?.({ current: next });
    };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [actionRef]);
  return (current?: number, pageSize?: number, total?: number) => {
    pageState.current = {
      current: current ?? 1,
      pageSize: pageSize ?? pageState.current.pageSize ?? 20,
      total: total ?? pageState.current.total ?? 0,
    };
  };
}
