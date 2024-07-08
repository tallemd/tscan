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
    public partial class ScanType : Form
    {
        public ScanType()
        {
            InitializeComponent();
            this.ServerListPath.Text = System.IO.Path.Combine(System.IO.Directory.GetCurrentDirectory(), "Serverlist.txt");
            this.Subnet.Enabled = false;
            foreach (System.Net.NetworkInformation.NetworkInterface Interface in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
            {
                foreach (System.Net.NetworkInformation.UnicastIPAddressInformation Address in Interface.GetIPProperties().UnicastAddresses)
                {
                    if (Interface.OperationalStatus != System.Net.NetworkInformation.OperationalStatus.Down &&
                            Address.IPv4Mask != null && "0.0.0.0" != Address.IPv4Mask.ToString() &&
                            !Address.Address.ToString().StartsWith("127", StringComparison.CurrentCultureIgnoreCase))
                    {
                        this.Subnet.Enabled = true;
                    }
                }
            }
            System.Diagnostics.PerformanceCounter RamCounter;
            RamCounter = new System.Diagnostics.PerformanceCounter("Memory", "Available MBytes");
            if (RamCounter.NextValue() < 300000) this.ScanInternet.Enabled = false; //300GB for a 4E12 item dictionary
            if (!this.Subnet.Enabled) this.ScanInternet.Enabled = false;
        }

        private void Next_Click(object sender, EventArgs e)
        {
            Tscan.Scan = new Scanner();
            //Tscan.Scan.WMIPasswords[0] = this.PasswordTextBox.Text;
            if (this.ActiveDirectory.Checked)
            {
                Tscan.Scan.IntScanType = 4;
            }
            else if (this.Subnet.Checked)
            {
                Tscan.Scan.IntScanType = 3;
            }
            else if (this.ServerList.Checked)
            {
                Tscan.Scan.IntScanType = 2;
                Tscan.Scan.ServerListFilename = this.ServerListPath.Text;
            }
            else if (this.thismachine.Checked)
            {
                Tscan.Scan.IntScanType = 1;
            }
            Tscan.Scan.ADOnly = this.ADOnly.Checked;
            Tscan.Scan.ScanInternet = this.ScanInternet.Checked;
            new Remote().ShowDialog();
            this.Close();
        }
    }
}
