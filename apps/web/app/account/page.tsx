import { AccountView } from "./account-view";

export const metadata = {
  title: "Account · apm",
  description: "Manage your apm account, linked GitHub identity, two-factor authentication, passkeys, and CLI tokens.",
};

export default function AccountPage() {
  return <AccountView />;
}
