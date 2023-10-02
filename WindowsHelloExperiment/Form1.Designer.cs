namespace WindowsHelloExperiment
{
    partial class Form1
    {
        /// <summary>
        ///  Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        ///  Clean up any resources being used.
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
        ///  Required method for Designer support - do not modify
        ///  the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            WindowsHelloButton = new Button();
            helloDetaills = new RichTextBox();
            buttonWebAuthn = new Button();
            buttonListCredentials = new Button();
            SuspendLayout();
            // 
            // WindowsHelloButton
            // 
            WindowsHelloButton.Location = new Point(12, 12);
            WindowsHelloButton.Name = "WindowsHelloButton";
            WindowsHelloButton.Size = new Size(161, 25);
            WindowsHelloButton.TabIndex = 0;
            WindowsHelloButton.Text = "Windows Hello";
            WindowsHelloButton.UseVisualStyleBackColor = true;
            WindowsHelloButton.Click += WindowsHelloButton_Click;
            // 
            // helloDetaills
            // 
            helloDetaills.Location = new Point(12, 54);
            helloDetaills.Name = "helloDetaills";
            helloDetaills.ReadOnly = true;
            helloDetaills.Size = new Size(512, 292);
            helloDetaills.TabIndex = 1;
            helloDetaills.Text = "";
            helloDetaills.TextChanged += richTextBox1_TextChanged;
            // 
            // buttonWebAuthn
            // 
            buttonWebAuthn.Location = new Point(196, 12);
            buttonWebAuthn.Name = "buttonWebAuthn";
            buttonWebAuthn.Size = new Size(161, 25);
            buttonWebAuthn.TabIndex = 2;
            buttonWebAuthn.Text = "Webauthn";
            buttonWebAuthn.UseVisualStyleBackColor = true;
            buttonWebAuthn.Click += buttonWebAuthn_Click;
            // 
            // buttonListCredentials
            // 
            buttonListCredentials.Location = new Point(387, 14);
            buttonListCredentials.Name = "buttonListCredentials";
            buttonListCredentials.Size = new Size(137, 23);
            buttonListCredentials.TabIndex = 3;
            buttonListCredentials.Text = "List Credentials";
            buttonListCredentials.UseVisualStyleBackColor = true;
            buttonListCredentials.Click += buttonListCredentials_Click;
            // 
            // Form1
            // 
            AutoScaleDimensions = new SizeF(7F, 15F);
            AutoScaleMode = AutoScaleMode.Font;
            ClientSize = new Size(552, 358);
            Controls.Add(buttonListCredentials);
            Controls.Add(buttonWebAuthn);
            Controls.Add(helloDetaills);
            Controls.Add(WindowsHelloButton);
            Name = "Form1";
            Text = "Form1";
            ResumeLayout(false);
        }

        #endregion

        private Button WindowsHelloButton;
        private RichTextBox helloDetaills;
        private Button buttonWebAuthn;
        private Button buttonListCredentials;
    }
}