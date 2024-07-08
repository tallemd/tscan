namespace Tscan
{
    partial class ScanType
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.thismachine = new System.Windows.Forms.RadioButton();
            this.Next = new System.Windows.Forms.Button();
            this.ServerList = new System.Windows.Forms.RadioButton();
            this.Subnet = new System.Windows.Forms.RadioButton();
            this.ActiveDirectory = new System.Windows.Forms.RadioButton();
            this.ServerListPath = new System.Windows.Forms.TextBox();
            this.ADOnly = new System.Windows.Forms.CheckBox();
            this.ScanInternet = new System.Windows.Forms.CheckBox();
            this.SuspendLayout();
            // 
            // thismachine
            // 
            this.thismachine.AutoSize = true;
            this.thismachine.Checked = true;
            this.thismachine.Location = new System.Drawing.Point(12, 12);
            this.thismachine.Name = "thismachine";
            this.thismachine.Size = new System.Drawing.Size(84, 17);
            this.thismachine.TabIndex = 0;
            this.thismachine.TabStop = true;
            this.thismachine.Text = "this machine";
            this.thismachine.UseVisualStyleBackColor = true;
            // 
            // Next
            // 
            this.Next.Location = new System.Drawing.Point(197, 227);
            this.Next.Name = "Next";
            this.Next.Size = new System.Drawing.Size(75, 23);
            this.Next.TabIndex = 1;
            this.Next.Text = "Next";
            this.Next.UseVisualStyleBackColor = true;
            this.Next.Click += new System.EventHandler(this.Next_Click);
            // 
            // ServerList
            // 
            this.ServerList.AutoSize = true;
            this.ServerList.Location = new System.Drawing.Point(12, 36);
            this.ServerList.Name = "ServerList";
            this.ServerList.Size = new System.Drawing.Size(69, 17);
            this.ServerList.TabIndex = 2;
            this.ServerList.Text = "server list";
            this.ServerList.UseVisualStyleBackColor = true;
            // 
            // Subnet
            // 
            this.Subnet.AutoSize = true;
            this.Subnet.Location = new System.Drawing.Point(13, 60);
            this.Subnet.Name = "Subnet";
            this.Subnet.Size = new System.Drawing.Size(57, 17);
            this.Subnet.TabIndex = 3;
            this.Subnet.Text = "subnet";
            this.Subnet.UseVisualStyleBackColor = true;
            // 
            // ActiveDirectory
            // 
            this.ActiveDirectory.AutoSize = true;
            this.ActiveDirectory.Location = new System.Drawing.Point(13, 84);
            this.ActiveDirectory.Name = "ActiveDirectory";
            this.ActiveDirectory.Size = new System.Drawing.Size(97, 17);
            this.ActiveDirectory.TabIndex = 4;
            this.ActiveDirectory.Text = "active directory";
            this.ActiveDirectory.UseVisualStyleBackColor = true;
            // 
            // ServerListPath
            // 
            this.ServerListPath.Location = new System.Drawing.Point(121, 36);
            this.ServerListPath.Name = "ServerListPath";
            this.ServerListPath.Size = new System.Drawing.Size(142, 20);
            this.ServerListPath.TabIndex = 5;
            this.ServerListPath.Text = "c:\\serverlist.txt";
            // 
            // ADOnly
            // 
            this.ADOnly.AutoSize = true;
            this.ADOnly.Location = new System.Drawing.Point(121, 84);
            this.ADOnly.Name = "ADOnly";
            this.ADOnly.Size = new System.Drawing.Size(47, 17);
            this.ADOnly.TabIndex = 6;
            this.ADOnly.Text = "Only";
            this.ADOnly.UseVisualStyleBackColor = true;
            // 
            // ScanInternet
            // 
            this.ScanInternet.AutoSize = true;
            this.ScanInternet.Location = new System.Drawing.Point(121, 60);
            this.ScanInternet.Name = "ScanInternet";
            this.ScanInternet.Size = new System.Drawing.Size(62, 17);
            this.ScanInternet.TabIndex = 7;
            this.ScanInternet.Text = "Internet";
            this.ScanInternet.UseVisualStyleBackColor = true;
            // 
            // scantype
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(284, 262);
            this.Controls.Add(this.ScanInternet);
            this.Controls.Add(this.ADOnly);
            this.Controls.Add(this.ServerListPath);
            this.Controls.Add(this.ActiveDirectory);
            this.Controls.Add(this.Subnet);
            this.Controls.Add(this.ServerList);
            this.Controls.Add(this.Next);
            this.Controls.Add(this.thismachine);
            this.Name = "scantype";
            this.Text = "tscan scan type";
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.RadioButton thismachine;
        private System.Windows.Forms.Button Next;
        private System.Windows.Forms.RadioButton ServerList;
        private System.Windows.Forms.RadioButton Subnet;
        private System.Windows.Forms.RadioButton ActiveDirectory;
        private System.Windows.Forms.TextBox ServerListPath;
        private System.Windows.Forms.CheckBox ADOnly;
        private System.Windows.Forms.CheckBox ScanInternet;
    }
}

