# cyberark-platform-cleanup
Python &amp; PowerShell scripts to clean up unused platforms in CyberArk PAM (self-hosted). Builds a per-platform report (account count, safes, last password change, last human use), then deactivates/deletes only the platforms you approve in the CSV. Dry-run by default, live re-validation, onboarding-rule checks, export backup before delete.
