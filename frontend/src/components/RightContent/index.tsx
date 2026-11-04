import { BookOutlined } from '@ant-design/icons';
import { history, useIntl } from '@umijs/max';
import { Button, Tooltip } from 'antd';
import React from 'react';
import { LangDropdown } from './LangDropdown';
import useHeaderActionStyles from './style';

export const DocLink: React.FC = () => {
  const { styles } = useHeaderActionStyles();
  const intl = useIntl();
  const label = intl.formatMessage({
    id: 'globalHeader.help',
    defaultMessage: '使用文档',
  });
  return (
    <Tooltip title={label}>
      <Button
        type="text"
        className={styles.action}
        icon={<BookOutlined />}
        aria-label={label}
        onClick={() => {
          history.push('/welcome');
        }}
      />
    </Tooltip>
  );
};

export { LangDropdown };
