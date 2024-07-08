namespace Tscan
{
    partial class Remote
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
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(Remote));
            this.labelPassword = new System.Windows.Forms.Label();
            this.labelSearchTerms = new System.Windows.Forms.Label();
            this.labelWMIObjects = new System.Windows.Forms.Label();
            this.textPassword = new System.Windows.Forms.TextBox();
            this.textSearchTerms = new System.Windows.Forms.TextBox();
            this.textWMIObjects = new System.Windows.Forms.TextBox();
            this.Next = new System.Windows.Forms.Button();
            this.textScript = new System.Windows.Forms.TextBox();
            this.labelScript = new System.Windows.Forms.Label();
            this.labelMAC = new System.Windows.Forms.Label();
            this.textMACURI = new System.Windows.Forms.TextBox();
            this.textElement = new System.Windows.Forms.TextBox();
            this.labelElement = new System.Windows.Forms.Label();
            this.Pass = new System.Windows.Forms.CheckBox();
            this.SuspendLayout();
            // 
            // labelPassword
            // 
            this.labelPassword.AutoSize = true;
            this.labelPassword.Location = new System.Drawing.Point(24, 23);
            this.labelPassword.Margin = new System.Windows.Forms.Padding(6, 0, 6, 0);
            this.labelPassword.Name = "labelPassword";
            this.labelPassword.Size = new System.Drawing.Size(106, 25);
            this.labelPassword.TabIndex = 0;
            this.labelPassword.Text = "Password";
            // 
            // labelSearchTerms
            // 
            this.labelSearchTerms.AutoSize = true;
            this.labelSearchTerms.Location = new System.Drawing.Point(24, 73);
            this.labelSearchTerms.Margin = new System.Windows.Forms.Padding(6, 0, 6, 0);
            this.labelSearchTerms.Name = "labelSearchTerms";
            this.labelSearchTerms.Size = new System.Drawing.Size(102, 25);
            this.labelSearchTerms.TabIndex = 1;
            this.labelSearchTerms.Text = "Find Text";
            // 
            // labelWMIObjects
            // 
            this.labelWMIObjects.AutoSize = true;
            this.labelWMIObjects.Location = new System.Drawing.Point(24, 123);
            this.labelWMIObjects.Margin = new System.Windows.Forms.Padding(6, 0, 6, 0);
            this.labelWMIObjects.Name = "labelWMIObjects";
            this.labelWMIObjects.Size = new System.Drawing.Size(134, 25);
            this.labelWMIObjects.TabIndex = 2;
            this.labelWMIObjects.Text = "WMI Objects";
            // 
            // textPassword
            // 
            this.textPassword.Location = new System.Drawing.Point(218, 17);
            this.textPassword.Margin = new System.Windows.Forms.Padding(6);
            this.textPassword.Name = "textPassword";
            this.textPassword.Size = new System.Drawing.Size(196, 31);
            this.textPassword.TabIndex = 3;
            // 
            // textSearchTerms
            // 
            this.textSearchTerms.Location = new System.Drawing.Point(218, 67);
            this.textSearchTerms.Margin = new System.Windows.Forms.Padding(6);
            this.textSearchTerms.Name = "textSearchTerms";
            this.textSearchTerms.Size = new System.Drawing.Size(196, 31);
            this.textSearchTerms.TabIndex = 4;
            this.textSearchTerms.Text = "2000,2003,10,11";
            // 
            // textWMIObjects
            // 
            this.textWMIObjects.Location = new System.Drawing.Point(218, 117);
            this.textWMIObjects.Margin = new System.Windows.Forms.Padding(6);
            this.textWMIObjects.Name = "textWMIObjects";
            this.textWMIObjects.Size = new System.Drawing.Size(196, 31);
            this.textWMIObjects.TabIndex = 5;
            this.textWMIObjects.Text = "win32_operatingsystem,win32_networkadapterconfiguration";
            // 
            // Next
            // 
            this.Next.Location = new System.Drawing.Point(394, 437);
            this.Next.Margin = new System.Windows.Forms.Padding(6);
            this.Next.Name = "Next";
            this.Next.Size = new System.Drawing.Size(150, 44);
            this.Next.TabIndex = 6;
            this.Next.Text = "Next";
            this.Next.UseVisualStyleBackColor = true;
            this.Next.Click += new System.EventHandler(this.Next_Click);
            // 
            // textScript
            // 
            this.textScript.Location = new System.Drawing.Point(218, 167);
            this.textScript.Margin = new System.Windows.Forms.Padding(6);
            this.textScript.Name = "textScript";
            this.textScript.Size = new System.Drawing.Size(196, 31);
            this.textScript.TabIndex = 7;
            this.textScript.Text = resources.GetString("textScript.Text");
            // 
            // labelScript
            // 
            this.labelScript.AutoSize = true;
            this.labelScript.Location = new System.Drawing.Point(24, 173);
            this.labelScript.Margin = new System.Windows.Forms.Padding(6, 0, 6, 0);
            this.labelScript.Name = "labelScript";
            this.labelScript.Size = new System.Drawing.Size(67, 25);
            this.labelScript.TabIndex = 8;
            this.labelScript.Text = "Script";
            // 
            // labelMAC
            // 
            this.labelMAC.AutoSize = true;
            this.labelMAC.Location = new System.Drawing.Point(24, 223);
            this.labelMAC.Margin = new System.Windows.Forms.Padding(6, 0, 6, 0);
            this.labelMAC.Name = "labelMAC";
            this.labelMAC.Size = new System.Drawing.Size(136, 25);
            this.labelMAC.TabIndex = 9;
            this.labelMAC.Text = "MAC Lookup";
            // 
            // textMACURI
            // 
            this.textMACURI.Location = new System.Drawing.Point(218, 217);
            this.textMACURI.Margin = new System.Windows.Forms.Padding(6);
            this.textMACURI.Name = "textMACURI";
            this.textMACURI.Size = new System.Drawing.Size(196, 31);
            this.textMACURI.TabIndex = 10;
            this.textMACURI.Text = "https://api.macvendors.com/\'MAC\'";
            // 
            // textElement
            // 
            this.textElement.Location = new System.Drawing.Point(218, 267);
            this.textElement.Margin = new System.Windows.Forms.Padding(6);
            this.textElement.Name = "textElement";
            this.textElement.Size = new System.Drawing.Size(196, 31);
            this.textElement.TabIndex = 11;
            this.textElement.Text = "result,company";
            // 
            // labelElement
            // 
            this.labelElement.AutoSize = true;
            this.labelElement.Location = new System.Drawing.Point(22, 273);
            this.labelElement.Margin = new System.Windows.Forms.Padding(6, 0, 6, 0);
            this.labelElement.Name = "labelElement";
            this.labelElement.Size = new System.Drawing.Size(90, 25);
            this.labelElement.TabIndex = 12;
            this.labelElement.Text = "Element";
            // 
            // Pass
            // 
            this.Pass.AutoSize = true;
            this.Pass.Location = new System.Drawing.Point(29, 307);
            this.Pass.Name = "Pass";
            this.Pass.Size = new System.Drawing.Size(239, 29);
            this.Pass.TabIndex = 13;
            this.Pass.Text = "Password Discovery";
            this.Pass.UseVisualStyleBackColor = true;
            // 
            // Remote
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(12F, 25F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(568, 504);
            this.Controls.Add(this.Pass);
            this.Controls.Add(this.labelElement);
            this.Controls.Add(this.textElement);
            this.Controls.Add(this.textMACURI);
            this.Controls.Add(this.labelMAC);
            this.Controls.Add(this.labelScript);
            this.Controls.Add(this.textScript);
            this.Controls.Add(this.Next);
            this.Controls.Add(this.textWMIObjects);
            this.Controls.Add(this.textSearchTerms);
            this.Controls.Add(this.textPassword);
            this.Controls.Add(this.labelWMIObjects);
            this.Controls.Add(this.labelSearchTerms);
            this.Controls.Add(this.labelPassword);
            this.Margin = new System.Windows.Forms.Padding(6);
            this.Name = "Remote";
            this.Text = "Remote";
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Label labelPassword;
        private System.Windows.Forms.Label labelSearchTerms;
        private System.Windows.Forms.Label labelWMIObjects;
        private System.Windows.Forms.TextBox textPassword;
        private System.Windows.Forms.TextBox textSearchTerms;
        private System.Windows.Forms.TextBox textWMIObjects;
        private System.Windows.Forms.Button Next;
        private System.Windows.Forms.TextBox textScript;
        private System.Windows.Forms.Label labelScript;
        private System.Windows.Forms.Label labelMAC;
        private System.Windows.Forms.TextBox textMACURI;
        private System.Windows.Forms.TextBox textElement;
        private System.Windows.Forms.Label labelElement;
        private System.Windows.Forms.CheckBox Pass;
    }
}