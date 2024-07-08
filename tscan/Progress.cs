using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;

namespace Tscan
{
    public partial class Progress : Form
    {
        public Progress()
        {
            InitializeComponent();
        }

        private void Close_Click(object sender, EventArgs e)
        {
            this.Close();
        }
        public void UpdateProgress(String ProgressLabel)
        {
            this.ProgressLabel.Text = ProgressLabel.ToString();
        }
        private void Progress_Load(object sender, EventArgs e)
        {
            Tscan.Scan.ScanNetQueueWorkItem(this.ProgressLabel.Text);
            //System.Threading.Thread.Sleep(TimeSpan.FromHours(10));
        }
    }
}
