using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows.Forms;
using MySql.Data.MySqlClient;
using static System.Windows.Forms.VisualStyles.VisualStyleElement.ListView;
using static Mysqlx.Expect.Open.Types.Condition.Types;

namespace TestedoMomento
{
    public partial class FormUsuario : Form
    {

        private MySqlConnection conexao;
        string data_source = "Server=localhost;Database=info06;Uid=root;Pwd=yes"; //fazer conexão com o banco de dados
        private readonly byte[] chave = GerarChave256Bits(); //criacão de criptografia
        public FormUsuario()
        {
            InitializeComponent();
            ConfigurarlistView();
        }

        private void ConfigurarlistView() //configurando o listeview para o cadastro ja registrado.
        {
            listView1.View =  View.Details;
            listView1.LabelEdit = true;
            listView1.AllowColumnReorder = true;
            listView1.FullRowSelect = true;
            listView1.Columns.Add("id", 50);
            listView1.Columns.Add("nome", 100);
            listView1.Columns.Add("cpf", 110);
            listView1.Columns.Add("endereço", 100);
            listView1.Columns.Add("numero", 50);
            listView1.Columns.Add("complemento", 100);
            listView1.Columns.Add("cidade", 100);
            listView1.Columns.Add("uf", 40);
            listView1.Columns.Add("email", 100);
            listView1.Columns.Add("senha", 255);
        }

        private void butSalvar_Click(object sender, EventArgs e)
        {
            try
            {
                using (conexao = new MySqlConnection(data_source)) 
                {
                    string sql = "Insert(id, nome,cpf,endereço,numero,complemento,bairro,cidade,email,senha)" +
                        "VALUES (@nome,@cpf,@endereço,@numero,@complemento,@bairro,@cidade,@email,@senha)";

                    using (MySqlCommand comando = new MySqlCommand(sql, conexao))
                    {

                        string senha = txtSenha.Text;

                        if (!ValidarSenha(senha)) //tem que atender os criterios da senha
                        {
                            MessageBox.Show("A senha não atende aos criterios de segurança.");
                            MessageBox.Show("Pelo menos 8 caracteres de comprimento.\nPelo menos uma letra maiuscula (A-Z).\nPelo menos uma letra minuscula (a-z).\nPelo menos um digito númerico (8-9).\nPelo menos um caractere especial (!, @, #, $, %, etc.\nNão conter caractere repetidos consecutivos.");
                            return;
                        }

                        string senhaCriptografada = CriptografarSenhaAES(senha);

                        comando.Parameters.AddWithValue("@nome", txtNome);
                        comando.Parameters.AddWithValue("@cpf", maskCpf);
                        comando.Parameters.AddWithValue("@endereço", txtEndereco);
                        comando.Parameters.AddWithValue("@numero", txtNumero);
                        comando.Parameters.AddWithValue("@complemento", txtComplemento);
                        comando.Parameters.AddWithValue("@bairro", txtBairro);
                        comando.Parameters.AddWithValue("@cidade", txtCidade);
                        comando.Parameters.AddWithValue("@email", txtEmail);
                        comando.Parameters.AddWithValue("@senha", senhaCriptografada); // Após feito a senha não deixar de atribuir a senha no comando para não dar erro.

                        conexao.Open();
                        comando.ExecuteNonQuery();
                    }
                    MessageBox.Show("Dados inseridos com sucesso!");
                    txtNome.Clear();
                }
            }

            catch (Exception ex)
            {
                MessageBox.Show($"Erro:{ex.Message}\n{ex.StackTrace}");
            }
        }

        private string CriptografarSenhaAES(string senha)
        {
            if (chave.Length != 32)
                throw new ArgumentException("A chave deve ter exatamente 32 bytes)");  

            byte[] iv = GerarIV();  //começou a contar os bites

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = chave;
                aesAlg.IV = iv; //inicializaçao de vetor, carregar o vetor e colocar na senha

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV); // metodo de criptografia, exige que asenha tenha 32bytes 

                using (MemoryStream msEncrypt = new MemoryStream()) //a ciona a memoria do banco para fazer uma tranação
                {
                    using (CryptoStream csStream = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write)) //mandar a memoria
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csStream)) 
                        {
                            swEncrypt.Write(senha);
                        }
                        byte[] encryptedContent = msEncrypt.ToArray();
                        byte[] result = new byte[encryptedContent.Length]; //pega o tamanho do inicializador do vetor, contate na ção
                        Buffer.BlockCopy(iv, 0, result, 0, iv.Length); //esta separando a memroria para aconcer uma coisa 
                        Buffer.BlockCopy(encryptedContent, 0, result, iv.Length, encryptedContent.Length); // tamanho da cryptografia
                        return Convert.ToBase64String(result); // caso de errada valta ao tamanho de 64
                    }
                }
            }
        }
        private static byte[] GerarIV()
        {
            using (var rng = new RNGCryptoServiceProvider())
            {
                byte[] iv = new byte[16];
                rng.GetBytes(iv);
                return iv;
            }

        }


        private static byte[] GerarChave256Bits()
        {
            //Gerando uma chave fixa
            byte[] chave = Encoding.UTF8.GetBytes("12345678901234567890123456789012");
            return chave;
        }

        private bool ValidarSenha(string senha)
        {
            if (senha.Length < 8) // esta ligado a uma confirmação de senha digitado menor que 8
            {
                return false;
            }
            if (!Regex.IsMatch(senha, @"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^\da-zA-Z]).{8,}$"))  // dizendo o que o usuario va precisar para colaocar na senha 
            {
                return false ; //vai retonar caso o objeto não seja atendido
            }
            
            for (int i = 0; i < senha.Length - 1; i++) //verifica a senha do usuario se esta certo ou errado 
            {
                if (senha[i] == senha[i + 1])
                {
                    return false;
                }

                
            }
            return true;
            {
                
            }
        }

        private void button1_Click(object sender, EventArgs e)
        {
            try
            {
                using (conexao = new MySqlConnection(data_source))
                {
                    string query = "%" + button1.Text + "%";
                    string sql = "SELECT id, nome,cpf,endereço,numero,complemento,bairro,cidade,email,senha"+
                    "FROM usuario WHERE nome LIKE @query";

                    conexao.Open();
                    MySqlCommand comando = new MySqlCommand(sql, conexao);
                    comando.Parameters.AddWithValue("@query", query);
                    MySqlDataReader reader = comando.ExecuteReader();

                    listView1.Items.Clear(); //limpar o listView antes de adicionar o item

                    if(!reader.HasRows)
                    {
                        MessageBox.Show("Nenhum registro encontrado");
                        return;
                    }

                    while(reader.Read())
                    {
                        // LER OS DADOS DO ARMAZENAMENTO ou ARMAZENADOS
                        string id = reader.IsDBNull(1) ? string.Empty : reader.GetInt32(1).ToString();
                        string cpf = reader.IsDBNull(2) ? string.Empty : reader.GetString(2);
                        string endereço = reader.IsDBNull(3) ? string.Empty : reader.GetString(3);
                        string numero = reader.IsDBNull(4) ? string.Empty : reader.GetString(4);
                        string complemento = reader.IsDBNull(5) ? string.Empty : reader.GetString(5);
                        string bairro = reader.IsDBNull(6) ? string.Empty : reader.GetString(6);
                        string cidade = reader.IsDBNull(7) ? string.Empty : reader.GetString(7);
                        string email = reader.IsDBNull(8) ? string.Empty : reader.GetString(8);
                        string senha = reader.IsDBNull(9) ? string.Empty : reader.GetString(9);
                        string nome = reader.IsDBNull(10) ? string.Empty : reader.GetString(10);

                        string[] row = { id, nome, cpf, endereço, numero, complemento, bairro, cidade, email, senha };

                        var linha_listview = new ListViewItem(row);
                        listView1.Items.Add(linha_listview);
                    }
                }
            }

            catch (Exception ex)    
            {
                MessageBox.Show($"Erro:{ex.Message}\n{ex.StackTrace}");
            }
        }

        private void listView1_DoubleClick(object sender, EventArgs e)
        {
            if (listView1.SelectedItems.Count > 0) //selecionando do listview o que ja esta cadastrado no sistema pelo sql
            {
                ListViewItem item = listView1.SelectedItems[0];
                txtNome.Text = item.SubItems[1].Text;
                maskCpf.Text = item.SubItems[2].Text;
                txtEndereco.Text = item.SubItems[3].Text;
                txtNumero.Text = item.SubItems[4].Text;
                txtComplemento.Text = item.SubItems[5].Text;
                txtBairro.Text = item.SubItems[6].Text;
                txtCidade.Text = item.SubItems[7].Text; 
                txtUF.Text = item.SubItems[8].Text;
                txtEmail.Text = item.SubItems[9].Text;
                txtSenha.Text = item.SubItems[10].Text;
            }
        }
    }

    }

