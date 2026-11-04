import { createStyles } from 'antd-style';
import React from 'react';

const useStyles = createStyles(({ token }) => ({
  footer: {
    padding: '24px',
    textAlign: 'center',
    color: token.colorTextDescription,
    fontSize: 13,
    letterSpacing: 2,
    background: 'transparent',
  },
}));

/** 登录页与业务布局共用品牌署名，避免暴露模板和构建工具链接。 */
const Footer: React.FC = () => {
  const { styles } = useStyles();
  return <footer className={styles.footer}>通研技术</footer>;
};

export default Footer;
