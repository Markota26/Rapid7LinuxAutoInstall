import paramiko
from scp import SCPClient

# Lista de servidores
file = "servidores.txt"
port = 22 
file_to_send = 'rapid7-agent-install.sh'  # Altere para o caminho do arquivo que deseja enviar

def ssh(ip, user, password, file_to_send, token):
# Função para criar cliente SCP
    def create_scp_client(ssh_client):
        return SCPClient(ssh_client.get_transport())

    # Criar cliente SSH
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        # Conectar ao servidor SSH
        ssh_client.connect(ip, port, user, password)
        print(f"Conectado ao servidor SSH: {ip}")

        # Enviar arquivo via SCP
        scp_client = create_scp_client(ssh_client)
        scp_client.put(file_to_send, './')
        scp_client.put('massive-ssh-rapid7-install.py', './')
        scp_client.put('servidores.txt', './')
        
        print(f"Arquivo enviado para: {ip}")
        print(password)
        print(token)
        
        # Executar comando
        #stdin, stdout, stderr = ssh_client.exec_command(f"echo {0} | sudo -S ./rapid7-agent-install.sh {1}".format(password, token))
        stdin, stdout, stderr = ssh_client.exec_command(f"echo {password} | sudo -S bash {file_to_send} {token}")
        # Ler e imprimir a saída
        for line in stdout:
            with open(f'{ip}.txt', 'a') as f:
                f.write(line)
            print(line.strip())
        for line in stderr:
            print(line.strip())
        for line in stdin:
            print(line.strip())
        print(f"Executado")

        # Verificar o status do serviço
        #stdin, stdout, stderr = ssh_client.exec_command(f'systemctl status ir_agent')
        #for line in stdout:
        #    print(line.strip())

    except paramiko.AuthenticationException:
        print("Falha na autenticação, por favor verifique suas credenciais.")
    except paramiko.SSHException as ssh_err:
        print(f"Incapaz de estabelecer conexão SSH: {ssh_err}")
    except Exception as e:
        print(f"Erro ao enviar arquivo ou executar comando: {e}")
    finally:
        # Fechar conexão SSH e SCP
        ssh_client.close()
        #scp_client.close()

def main():

    token = str(input("Insira o token:"))

    with open(file, "r") as f:
        #lista = [line.strip() for line in f]

        for line in f:
            line = line.rstrip()
            linef = line.split(';')
            ip = linef[0]
            user = linef[1]
            password = linef[2]
            ssh(ip,user,password,file_to_send, token)



	# Ao iniciar o script ele deve checar se todos os hosts possuem usuario e senha, se nao ouver, deve pedir o usuario e senha default.
    # EXEMPLO: 192.168.25.184;admin;senha@123
	# Após o passo acima, deve pedir o token do Rapid7 para efetuar a instalação
    # Após instalar cada maquina, o script deve exibir na tela a saida do comando “systemctl status insight-agent” (validar nome do serviço).
    # A conexão deve ser SSH, o envio do arquivo para a maquina deve ser via scp,

main()
