#!/usr/bin/python3

# Importa bibliotecas necessárias
import os
import yara
import time
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer
import psutil
import subprocess
import wmi

# Diretório de Regras YARA
YARA_RULES_DIR = "rules"

class YaraClass:
    """Caminha pelo diretório, compilando e testando regras, e escaneando arquivos
    """
    def __init__(self):
        """Inicialização do YaraClass que configurao verbose, scan and diretório YARA
        """
        try:
            self.yara_dir = YARA_RULES_DIR
            self.verbose = False
            self.compile()
        except Exception as e:
            print ("Init Compile Exception: {}".format(e))

    def compile(self):
        """Caminha pelo diretório, testa regras, e compila elas para escanear
        """
        try:
            all_rules = {}
            for root, directories, files in os.walk(self.yara_dir):
                for file in files:
                    if "yar" in os.path.splitext(file)[1]:
                        rule_case = os.path.join(root, file)
                        if self.test_rule(rule_case):
                            all_rules[file] = rule_case
            self.rules = yara.compile(filepaths=all_rules)
        except Exception as e:
            print ("Compile Exception: {}".format(e))

    def test_rule(self, test_case):
        """Testa regras para ter certeza que elas são válidas para serem usadas.  Se a verbose estiver setada, irá printar as regras inválidas.
        """
        try:
            yara.compile(filepath=test_case)
            return True
        except:
            if self.verbose:
                print ("{} is an invalid rule".format(test_case))
            return False


    def scan(self, virus):
        """Método de scan baseado nas regras compiladas
        """
        try:
            matched_rules = []
            matches = self.rules.match(virus)
            for i in matches:
                matched_rules.append(i)                
            return matched_rules
           	
        except Exception as e:
            print ("'ERROR' - Scan Exception: {}".format(e))
            return 0

    def download(self, dir):
        for filename in os.listdir(dir):
            f = os.path.join(dir, filename)
            if os.path.isfile(f):
                self.scan(f)
                if self.scan(f):
                    print("Ameaça Detectada!")
                    os.remove(f)
                    print("Ameaça Removida!")

# --------------------------------------------------------------------------------------------------------

def getUserPATH():
    global dir
    name = os.getlogin()
    dir = "C:\\Users\\{0}\Downloads".format(name)

    return dir

# --------------------------------------------------------------------------------------------------------

def bait(dir):  # Cria arquivos 'bait' para o ransomware na pasta 'Downloads'
    for n in range(1, 100):
        with open(os.path.join(dir, f"bait {n}.txt"), "w") as arq:
            toArq = "this is bait ignore"
            arq.write(toArq)

# --------------------------------------------------------------------------------------------------------

def main():

    # Inicialização da YaraClass
    yara = YaraClass()
    regras = yara.compile()
    yara.test_rule(regras)

    useros = getUserPATH() 
    bait(useros)

    opt = int(input("Deseja fazer o que?\n1 - Escanear a pasta de 'Downloads'?\n2 - Verificar atividade maliciosa de algum executável?\n"))

    if opt == 1:
        print("Analisando agora.\nCaso nenhuma mensagem de ameaça aparecer ou alertar que a ameaça foi removida, pode fechar tranquilamente o programa!\n")
        yara.download(useros)

    elif opt == 2:

        c = wmi.WMI()
        process_watcher = c.Win32_Process.watch_for("creation")
        print("\nAnalisando agora evite de abrir outros programas.\nCaso nenhuma mensagem de ameaça aparecer ou alertar que a ameaça foi removida, pode fechar tranquilamente o programa!\n")
        while True:
            recent_proc = []
            new_process = process_watcher()
            if new_process not in recent_proc:
                recent_proc.append(new_process.ProcessId)
            else:
                if new_process in recent_proc:
                    recent_proc.remove(new_process.ProcessId)
            for pid in reversed(recent_proc):
                if pid != os.getpid():
                    subprocess.run(f"taskkill /PID {pid} /F /T", shell=True)
                    yara.download(useros)
            recent_proc.clear()
    
    else:
        print("Digite uma opção válida.")
        
        
if __name__ == "__main__":
    main()
