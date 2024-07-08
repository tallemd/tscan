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
    public partial class Remote : Form
    {
        public Remote()
        {
            InitializeComponent();
        }

        private void Next_Click(object sender, EventArgs e)
        {
            Tscan.Scan.Password = this.textPassword.Text;
            Tscan.Scan.DoPass = this.Pass.Checked;
            Tscan.Scan.WMIPasswords[0] = this.textPassword.Text;
            Tscan.Scan.SearchObjects = this.textWMIObjects.Text;
            Tscan.Scan.SearchTerm = this.textSearchTerms.Text;
            Tscan.Scan.RemoteExec.RemoteExecScript = this.textScript.Text;
            Tscan.Scan.MACLookupURI = this.textMACURI.Text;
            Tscan.Scan.XMLElements = this.textElement.Text.Split(",".ToCharArray());
            new Verify().ShowDialog();
            //Application.Run(new Verify());
            this.Close();
        }
    }
}
