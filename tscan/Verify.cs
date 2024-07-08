using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;

namespace Tscan
{
    public partial class Verify : Form
    {
        public Verify()
        {
            InitializeComponent();
            if (Tscan.Scan.IntScanType == 1) this.VerifyLabel.Text = "Do you want to scan this machine? " + System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().HostName;
            else if (Tscan.Scan.IntScanType == 2) this.VerifyLabel.Text = "Do you want to scan the contents of this server list? \n" + Tscan.Scan.ServerListFilename;
            else if (Tscan.Scan.IntScanType == 3 && Tscan.Scan.ScanInternet) this.VerifyLabel.Text = "Do you want to scan the internet? ";
            else if (Tscan.Scan.IntScanType == 3 && !Tscan.Scan.ScanInternet)
            {
                String Subnet = "";//System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces().First().GetIPProperties().UnicastAddresses.First().IPv4Mask.ToString();
                String MyIP = "";//System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces().First().GetIPProperties().UnicastAddresses.First().Address.ToString();
                foreach (System.Net.NetworkInformation.NetworkInterface Interface in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
                {
                    foreach (System.Net.NetworkInformation.UnicastIPAddressInformation Address in Interface.GetIPProperties().UnicastAddresses)
                    {
                        if (Interface.OperationalStatus != System.Net.NetworkInformation.OperationalStatus.Down &&
                            Address.IPv4Mask != null && "0.0.0.0" != Address.IPv4Mask.ToString() &&
                            !Address.Address.ToString().StartsWith("127", StringComparison.CurrentCultureIgnoreCase))
                        {
                            Subnet = Address.IPv4Mask.ToString();
                            MyIP = Address.Address.ToString();
                        }
                    }
                }
                this.VerifyLabel.Text = "Do you want to scan this subnet? " + Subnet + " " + MyIP;
            }
            else if (Tscan.Scan.IntScanType == 4) this.VerifyLabel.Text = "Do you want to scan this domain? " + System.Security.Principal.WindowsIdentity.GetCurrent().Name.Split('\\')[0];//ad
        }

        private void Next_Click(object sender, EventArgs e)
        {
            Tscan.Scan.ProgressForm = new Progress();
            Tscan.Scan.ProgressForm.ShowDialog();
            //Application.Run(new Progress());
            this.Close();
        }
    }
}
