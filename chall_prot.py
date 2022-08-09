# Import the required libraries
import os
import yara
import psutil
import time
from subprocess import call
from prettytable import PrettyTable

# Yara Rules Directory
YARA_RULES_DIR = "rules"

virus = "inserir arquivo aqui"

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


    def scan(self, scan_file):
        """Método de scan baseado nas regras compiladas
        """
        try:
            matched_rules = []
            matches = self.rules.match(scan_file)
            for i in matches:
                matched_rules.append(i)
            print(matched_rules)
            return matched_rules
        except Exception as e:
            print ("Scan Exception: {}".format(e))
            return 'ERROR'


def main():

    # Inicialização da YaraClass
    yara = YaraClass()

    # Chamando as funções
    # Compilando regras
    regras = yara.compile()

    # Testa as regras
    yara.test_rule(regras)

    # Escanea o ransomware
    #yara.scan(virus)

def main():# Run an infinite loop to constantly monitor the system
    while True:

        # Clear the screen using a bash command
        call('clear')

        print("==============================Process Monitor\
        ======================================")

        # Fetch the battery information
        #battery = psutil.sensors_battery().percent
        #print("----Battery Available: %d " % (battery,) + "%")

        # We have used PrettyTable to print the data on console.
        # t = PrettyTable(<list of headings>)
        # t.add_row(<list of cells in row>)

        # Fetch the Network information
        print("----Networks----")
        table = PrettyTable(['Network', 'Status', 'Speed'])
        for key in psutil.net_if_stats().keys():
                name = key
                up = "Up" if psutil.net_if_stats()[key].isup else "Down"
                speed = psutil.net_if_stats()[key].speed
                table.add_row([name, up, speed])
        print(table)

        # Fetch the memory information
        print("----Memory----")
        memory_table = PrettyTable(["Total(GB)", "Used(GB)",
                                                                "Available(GB)", "Percentage"])
        vm = psutil.virtual_memory()
        memory_table.add_row([
                f'{vm.total / 1e9:.3f}',
                f'{vm.used / 1e9:.3f}',
                f'{vm.available / 1e9:.3f}',
                vm.percent
        ])
        print(memory_table)

        # Fetch the 10 processes from available processes that has the highest cpu usage
        print("----Processes----")
        process_table = PrettyTable(['PID', 'PNAME', 'STATUS',
                                                                'CPU', 'NUM THREADS', 'MEMORY(MB)'])

        proc = []
        # get the pids from last which mostly are user processes
        for pid in psutil.pids()[-200:]:
                try:
                        p = psutil.Process(pid)
                        # trigger cpu_percent() the first time which leads to return of 0.0
                        p.cpu_percent()
                        proc.append(p)

                except Exception as e:
                        pass

        # sort by cpu_percent
        top = {}
        time.sleep(0.1)
        for p in proc:
                # trigger cpu_percent() the second time for masurement
                top[p] = p.cpu_percent() / psutil.cpu_count()

        top_list = sorted(top.items(), key=lambda x: x[1])
        top10 = top_list[-10:]
        top10.reverse()

        for p, cpu_percent in top10:

                # While fetching the processes, some of the subprocesses may exit
                # Hence we need to put this code in try-except block
                try:
                        # oneshot to improve info retrieve efficiency
                        with p.oneshot():
                                process_table.add_row([
                                        str(p.pid),
                                        p.name(),
                                        p.status(),
                                        f'{cpu_percent:.2f}' + "%",
                                        p.num_threads(),
                                        f'{p.memory_info().rss / 1e6:.3f}'
                                ])

                except Exception as e:
                        pass
        print(process_table)

        # Create a 1 second delay
        time.sleep(1)

if __name__ == "__main__":
    main()
