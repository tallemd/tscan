namespace Tscan
{
    partial class Progress
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
            this.ProgressLabel = new System.Windows.Forms.Label();
            this.AppClose = new System.Windows.Forms.Button();
            this.progressBarTotal = new System.Windows.Forms.ProgressBar();
            this.SuspendLayout();
            // 
            // ProgressLabel
            // 
            this.ProgressLabel.AutoSize = true;
            this.ProgressLabel.Location = new System.Drawing.Point(26, 25);
            this.ProgressLabel.Margin = new System.Windows.Forms.Padding(6, 0, 6, 0);
            this.ProgressLabel.Name = "ProgressLabel";
            this.ProgressLabel.Size = new System.Drawing.Size(98, 25);
            this.ProgressLabel.TabIndex = 0;
            this.ProgressLabel.Text = "Progress";
            // 
            // AppClose
            // 
            this.AppClose.Location = new System.Drawing.Point(394, 437);
            this.AppClose.Margin = new System.Windows.Forms.Padding(6, 6, 6, 6);
            this.AppClose.Name = "AppClose";
            this.AppClose.Size = new System.Drawing.Size(150, 44);
            this.AppClose.TabIndex = 1;
            this.AppClose.Text = "Close";
            this.AppClose.UseVisualStyleBackColor = true;
            this.AppClose.Click += new System.EventHandler(this.Close_Click);
            // 
            // progressBarTotal
            // 
            this.progressBarTotal.Location = new System.Drawing.Point(31, 437);
            this.progressBarTotal.Name = "progressBarTotal";
            this.progressBarTotal.Size = new System.Drawing.Size(334, 23);
            this.progressBarTotal.Style = System.Windows.Forms.ProgressBarStyle.Continuous;
            this.progressBarTotal.TabIndex = 2;
            this.progressBarTotal.Value = 10;
            // 
            // Progress
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(12F, 25F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(568, 504);
            this.Controls.Add(this.progressBarTotal);
            this.Controls.Add(this.AppClose);
            this.Controls.Add(this.ProgressLabel);
            this.Margin = new System.Windows.Forms.Padding(6, 6, 6, 6);
            this.Name = "Progress";
            this.Text = "Progress";
            this.Load += new System.EventHandler(this.Progress_Load);
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Button AppClose;
        public System.Windows.Forms.Label ProgressLabel;
        public System.Windows.Forms.ProgressBar progressBarTotal;
    }
}