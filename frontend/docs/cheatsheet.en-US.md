# Free SSL Certificate Manager User Guide

This guide covers cloud accounts, DNS, certificate issuance, deployment, recurring schedules, email reminders and configuration migration. Certificate applications and synchronization support Tencent Cloud and Alibaba Cloud. Administrators manage resources; viewers have read-only access.

## Quick start

1. Create the administrator account on the first-run setup page.
2. Add a cloud account in **Configuration**, enable the required certificate and DNS purposes, and test the connection.
3. Synchronize hosted zones in **Domains**, then synchronize existing certificates or apply for a new one in **SSL Certificates**.
4. For deployment, configure and test a **Deployment Target** first, then deploy from the certificate list. Use **Certificate Schedules** for recurring applications and deployment.
5. Configure SMTP and expiry reminders in **Mail**. The dashboard shows resource totals, status distributions and certificates approaching expiry.

## Configure cloud accounts

Open **Configuration** and add or edit an account:

- Select Tencent Cloud or Alibaba Cloud and enter the AccessKey and Secret.
- **Use for certificate management** controls certificate synchronization and applications.
- **Use for DNS management** controls hosted zones and DNS record synchronization.
- Account reads show masked keys. Leave key fields blank when editing to keep existing values. Use the reveal action when necessary; closing it hides the original value.
- Use **Test connection** to check permissions and quota. The result is shown in **Last check**.
- Alibaba Cloud contacts can be synchronized after entering the keys. Save a selected contact so certificate applications can reuse it. Links to the contact console and ListContact documentation are provided.
- Enable automatic synchronization and select minute, hour, day or month plus a local execution time. Enabled purposes decide whether domains or certificates are synchronized; runs are recorded in audit logs.

Grant certificate query, application, revocation, download, and DNS zone/record permissions according to the enabled purposes. Alibaba Cloud free certificate applications use CAS V2 and require an eligible free instance claimed in the cloud console. Quotas, certificate validity and API capabilities depend on the provider's actual response.

## Domain management

Open **Domains** and click sync. The platform retrieves a complete snapshot of hosted zones from accounts with DNS management enabled:

- Expand a domain row to view DNS records in the inline child table.
- Add, edit, enable, disable or delete DNS records.
- Records created for automatic certificate validation are marked; the application settings determine whether they are cleaned up automatically.
- Unstable cloud pagination is retried and validated before local data is replaced.

## SSL certificate management

Open **SSL Certificates**:

- Synchronize existing cloud certificates, or click Apply and select an enabled account with certificate management enabled.
- Enter a domain prefix and select or type its suffix. Leave the prefix blank for the root domain. Free applications support a single domain, without wildcards, a protocol or a path.
- Alibaba Cloud requires an unused, eligible free V2 instance already claimed by the selected account, together with an application contact.
- Choose cloud-native automatic DNS, platform-managed DNS, manual DNS or file validation. Platform-managed DNS uses a synchronized hosted zone covering the domain under the same application account; enable DNS management and synchronize that account's domains first.
- For manual DNS or file validation, follow the record or file path and content shown in certificate details. Automatic DNS can clean up after issuance, but only removes records created by that application that still match its validation snapshot. Failed cleanup can be retried from details.
- Check progress in the list or details after submitting. If the result needs verification, synchronize first to avoid duplicate applications and quota consumption.
- Filter by status, inspect details, download, revoke, cancel verification or delete where the current state and provider allow. Expired, revoked and cancelled certificates support bulk cleanup.
- Choose Nginx, IIS or Apache when downloading. Files use `domain-format-YYYYMMDD.zip`. Use **Deploy** on an issued certificate to send it to one or more targets.

## Deployment targets and records

1. Create a **Deployment Target** and choose an available executor matching the product and version. Current options include SafeLine Community Edition 9.x, Synology DSM 7.x, Linux SSH and Windows SSH. Windows WinRM is currently unavailable; use the available options shown on the page.
2. Enter the endpoint, authentication method, credentials and target configuration. Verify the SSH host fingerprint for SSH targets. Leave existing credential fields blank when editing to retain their values.
3. For Linux file targets, select an issued source certificate and download format, then map package files to remote absolute paths. Use the remote file browser to choose destinations and configure permissions, ownership, verification and post-deployment reload or restart commands as needed.
4. Save and enable the target, then **Test connection**. This checks authentication and capabilities without uploading certificates or running reload/restart commands.
5. Click **Deploy** in the certificate list, choose targets and **Generate deployment plan**. Review the certificate fingerprint, overwritten files, associated sites/services, commands and messages before confirming. Regenerate the plan after it expires or configuration changes.

Synology uses a DSM administrator password and currently does not support two-factor authentication. Replacing a certificate preserves its description, service associations and default state. Assign services for newly added certificates in DSM.

Submitted deployments run in the background; closing the dialog does not cancel them. **Deployment History** shows each target's status, phase, steps and verification result. File writes, platform updates and live HTTPS activation are recorded separately; use the verification result to assess activation.

- Request **Cancel subsequent steps** while a task is active. Completed remote changes are not automatically undone.
- For a task needing attention, inspect the remote state first. After manual verification, record the actual outcome to release the block; this does not declare the deployment successful.
- Failed or cancelled tasks can generate a new plan. Executors supporting file recovery can preview and restore backups from the original task. Recovery does not run reload, restart or other post-deployment commands; verify the service separately.

## Certificate schedules

Create a **Certificate Schedule** with an account, complete single domain, automatic DNS validation method, 1–20 deployment targets, first execution time and an hourly, daily or monthly interval. Page times use the Asia/Shanghai time zone. The account needs both certificate and DNS purposes enabled. Only one schedule for the same account and domain can be enabled. Schedules currently support SafeLine, Synology and Linux file targets; targets added later are not automatically included in existing schedules.

- Each background run applies for a certificate, waits for issuance, deploys to the selected targets and handles cleanup. The browser may close, but the backend service must keep running.
- Enable validation-record cleanup if needed. When **Revoke and delete old certificates** is enabled, old certificates within the schedule's scope are handled only after all targets succeed: valid certificates are revoked and confirmed before deletion; expired certificates are deleted directly.
- **Run now** starts one application/deployment run without changing the recurring anchor. Inspect application, target deployment and cleanup results in run history; use its recovery or manual verification actions to handle exceptions.
- Alibaba Cloud schedules select an available free instance and never purchase one automatically. Claim an instance in the cloud console if none is available.
- Disabling a schedule prevents subsequent cycles. Already submitted deployments remain manageable in **Deployment History**.

## Email and certificate expiry reminders

Administrators open **Mail** and configure the SMTP server, sender and authorization code/password in **Mail Settings**. Choose SSL/TLS or STARTTLS as required by the provider, save, test the connection, then send a test message and check the inbox. Leaving the saved authorization code blank preserves it.

- **Sent Records** lets you send mail, search history and inspect details. Records only include messages submitted by this system. **Submitted to mail server** means SMTP acceptance, not final delivery or reading. For an unknown result, inspect the original record or inbox before sending again.
- In **Expiry Reminders**, enable the rule and set the advance days, repeat interval and recipients. Defaults are 30 days in advance and a 1-day repeat interval; 0 means the initial reminder only. Reminders require configured, enabled SMTP and use the certificate validity last synchronized locally.
- Existing unresolved alerts continue after expiry until the original certificate's validity moves outside the reminder window, it is revoked/deleted, or the alert is manually ignored. Another new certificate for the same domain does not clear the original alert. Ignoring an alert cannot recall an already submitted email.

## Configuration import and export

Administrators use **Configuration Transfer** to migrate cloud accounts, deployment targets, certificate schedules, SMTP and expiry reminder rules between Web, container and desktop instances.

1. Export the JSON configuration. It includes plaintext credentials such as cloud keys, passwords, tokens and SSH private keys; store and transfer it in a trusted environment.
2. Select JSON exported by this system on the destination instance (up to 5 MiB and 1,000 configuration items). Choose **Create only** or **Update by name**, preview conflicts and changes, then confirm import.
3. A preview is valid for 15 minutes. Preview again after changing the file, mode or existing configuration. Configurations used by active tasks cannot be updated.
4. Imported items remain disabled and automatic synchronization is off. Verify account purposes, synchronize domains/certificates and test deployment targets before enabling each item.

Migration excludes login users, certificate files, run history, alert states and the original instance's key ring. It does not replace a complete database and encryption-key backup. If an import result is uncertain, inspect current configuration and audit records before reopening the page to continue.

## Dashboard

The dashboard counts enabled cloud accounts, hosted domains, certificates, issued certificates, certificates expiring within 30 days and expired certificates. It also shows provider and status distributions and a list of soon-to-expire certificates. Click a card to open its list or use refresh to reload statistics.

## Users and permissions

- **Administrator:** manage cloud accounts, synchronization, certificates, DNS, deployment targets and tasks, recurring schedules, email, configuration transfer, users and audit logs.
- **Viewer:** inspect the dashboard, domains and certificates. Write operations and certificate downloads require administrator permission.
- The avatar menu provides change password, theme settings and sign out. Changing a password requires the current password, a new password and confirmation.
- **Audit Logs** provides filters such as operator and action to inspect configuration, DNS, certificate and system-management operations and verify their outcomes.

## Theme and display

Open **Theme Settings** from the avatar menu in the top-right corner to adjust layout, overall style, primary color, fixed header and menu display. Enable **Follow system** beside the drawer title for automatic mode; the page updates when the operating system's light/dark preference changes. Selecting an existing light or dark card exits automatic mode. The theme mode is saved in the current browser, restored after refresh, and applies immediately to the menu, header and content.

Lists use a compact small density by default. Each table has independent density and column visibility settings saved in browser local storage. Use the left and right arrow keys to move between pages while the list is focused. The document button opens this guide; the language button switches between Simplified Chinese and English.

## Desktop client

The desktop client includes its local backend and database. Create an administrator on first use, then use the same certificate, DNS, deployment and schedule pages as the Web version. **Desktop Settings and Backup** provides window-close behavior, login startup, log locations and encrypted backup/restore.

- Closing the main window keeps the tray service running by default. Use **Quit completely** to stop the backend. Schedules do not run during shutdown, logout, sleep or complete exit. Restarting or waking resumes unfinished stages and catches up according to the cycle rules.
- An encrypted `.sslbak` backup preserves business data and encryption keys. Exit the original client before restoring and avoid running schedules from the same backup on two computers. Configuration JSON migrates settings and does not replace a full backup.

## Troubleshooting

### Alibaba Cloud MissingParameter

Select an Alibaba Cloud contact and confirm the free certificate instance specification in the console. The instance must be an unused basic instance in **Pending application**. Check that the AccessKey has permission to call CAS V2.

### Incomplete synchronization

Check the account purpose switches, pagination permissions and network connection, then sync again. Local data is updated only after a trusted complete snapshot is available.

### No selectable deployment targets or schedule accounts

Enable deployment targets and complete connection tests first. File-mapping targets must also match the certificate's primary domain. Schedule accounts need both certificate and DNS purposes enabled; synchronize that account's domains before using managed DNS validation.

### A service still presents the old certificate after deployment

Inspect the target's verification result and steps in deployment records. Check file paths, associated sites/services, and reload or restart commands. Successful file writes do not prove live HTTPS activation. Inspect the remote state first when a result needs attention, then handle the actual service state.

### Expiry reminders are not sent

Check that SMTP is configured and enabled, connection and test messages succeed, the reminder rule and recipients are enabled, and the certificate validity was recently synchronized. Then inspect alerts and sent records for the repeat interval and latest send outcome.

## Related API documents

- [Alibaba Cloud CAS V2 API](https://help.aliyun.com/zh/ssl-certificate/developer-reference/api-cas-2020-04-07-applycertificate)
- [Tencent Cloud DNSPod API](https://cloud.tencent.com/document/product/1427/56172)
- [Alibaba Cloud contact console](https://yundun.console.aliyun.com/?p=cas#/informationManagement/person/cn-hangzhou)
- [Alibaba Cloud ListContact documentation](https://help.aliyun.com/zh/ssl-certificate/developer-reference/api-cas-2020-04-07-listcontact)

