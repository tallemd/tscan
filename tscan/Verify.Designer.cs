namespace Tscan
{
    partial class Verify
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
            this.Next = new System.Windows.Forms.Button();
            this.VerifyLabel = new System.Windows.Forms.Label();
            this.SuspendLayout();
            // 
            // Next
            // 
            this.Next.Location = new System.Drawing.Point(197, 227);
            this.Next.Name = "Next";
            this.Next.Size = new System.Drawing.Size(75, 23);
            this.Next.TabIndex = 0;
            this.Next.Text = "Next";
            this.Next.UseVisualStyleBackColor = true;
            this.Next.Click += new System.EventHandler(this.Next_Click);
            // 
            // VerifyLabel
            // 
            this.VerifyLabel.Location = new System.Drawing.Point(13, 13);
            this.VerifyLabel.Name = "VerifyLabel";
            this.VerifyLabel.Size = new System.Drawing.Size(259, 143);
            this.VerifyLabel.TabIndex = 1;
            this.VerifyLabel.Text = "Verify";
            // 
            // Verify
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(284, 262);
            this.Controls.Add(this.VerifyLabel);
            this.Controls.Add(this.Next);
            this.Name = "Verify";
            this.Text = "Verify";
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.Button Next;
        private System.Windows.Forms.Label VerifyLabel;
    }
}