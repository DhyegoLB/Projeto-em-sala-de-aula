using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using MySql.Data.MySqlClient;

namespace TestedoMomento   //CRIANDO UMA CONEXAO NO FORM LOGIN QUE JA ETA CADASTRADO NO USUARIO, QUE DIRETAMENTE VAI PARA O LOGIN PARA O MENU DE ENTRADA.
{                         // AO FINALIZAR FAZER COM QUE O LOGIN SENHA A TELA INICIA APOS FAZER O CADASTRO DE ACESSO.
    public partial class FormLogin : Form
    {
        private MySqlConnection conexao;
        string data_source = "Server=localhost;Database=info06;Uid=root;Pwd=()"; //fazer conexão com o banco de dados
        private readonly byte[] chave = GerarChave256Bits(); //criacão de criptografia
        private readonly byte[] iv = GerarIV();
        public FormLogin()
        {
            InitializeComponent();
        }

        private void label1_Click(object sender, EventArgs e)
        {

        }

        private void textBox1_TextChanged(object sender, EventArgs e)
        {

        }

        private void button1_Click(object sender, EventArgs e)
        {
            string usuario = txtUsuario.Text;
            string senha = txtSenha.Text;

            try
            {
                using (conexao = new MySqlConnection(data_source))
                {
                    string sql = "SELECT senha FROM usuarios WHERE nome = @nome";
                    MySqlCommand comando = new MySqlCommand(sql, conexao);
                    comando.Parameters.AddWithValue("@nome", usuario);

                    conexao.Open();
                    object resultado = comando.ExecuteScalar();

                    if (resultado != null)
                    {
                        string senhaCriptografada = resultado.ToString();
                        string senhaDescriptografada = DescriptografarSenhaAES(senhaCriptografada);

                        if (senhaDescriptografada == senha)
                        {  //sENHA CORRETA ABRRIR FORMULARIO Form1 que é a tela principal.
                            Form1 form1 = new Form1();
                            form1.Show();
                            this.Hide();
                        }
                        else
                        {
                            MessageBox.Show("Usuario ou senha incorretos!");
                        }


                    }
                }
            }

            catch (Exception ex)
            {
                MessageBox.Show($"Erro: {ex.Message}\n{ex.StackTrace}");
            }
        }

        private string DescriptografarSenhaAES(string senhaCriptografada)
            {
            try
            {
                byte[] encryptoBytesWitchIV = Convert.FromBase64String(senhaCriptografada);
                byte[] iv = new byte[16];
                byte[] encryptoBytes = new byte[encryptoBytesWitchIV.Length - iv.Length];

                //Extrair o IV dos primeirs 16 bytes da senha criptografada
                Buffer.BlockCopy(encryptoBytesWitchIV, 0, iv, 0, iv.Length);
                //Extrair os bytes restantes criptografados
                Buffer.BlockCopy(encryptoBytesWitchIV, iv.Length, encryptoBytes, 0, encryptoBytes.Length);

                using (Aes aesAlg = Aes.Create())
                {
                    aesAlg.Key = chave;
                    aesAlg.IV = iv;

                    ICryptoTransform descryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                    using ( MemoryStream msDecrypt = new MemoryStream(encryptoBytes))
                    {
                        using (CryptoStream csDescrypt = new CryptoStream(msDecrypt, descryptor, CryptoStreamMode.Read))
                        {
                            using (StreamReader srDecrypt = new StreamReader(csDescrypt))
                            {
                                return srDecrypt.ReadToEnd();
                            }
                        }
                    }
                }

                }

            catch (Exception ex) 
            {
                MessageBox.Show($"Erro na descriptografia:{ex.Message}");
                return null;
            }

            }

        private static byte[] GerarChave256Bits()
        {
            //Chave de 32 bytes (256 bits)
            string chaveString = "1345678901234567890123456789012";
            return Encoding.UTF8.GetBytes( chaveString );
        }

        private static byte[] GerarIV()
        {
            //IV de 16 bytes
            using (var rng =  new RNGCryptoServiceProvider())
            {
                byte[] iv = new byte[16];
                rng.GetBytes( iv );
                return iv;
            }
        }

        }
    }


