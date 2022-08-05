import os
import yara

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

        print(all_rules)

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
    yara.scan(virus)

if __name__ == "__main__":
    main()
