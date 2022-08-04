import os
import yara
import math



# Yara Rules Directory
YARA_RULES_DIR = "rules"

virus = "pls.txt"

def get_entropy(input_file):
    """ Gets the entropy of file from Ero Carrerra's Blog
    http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html
    """
    try:
        with open(input_file, "rb") as open_file:
            data = open_file.read()
            if not data: 
                return 0 
            entropy = 0 
            for x in range(256): 
                p_x = float(data.count(chr(x)))/len(data) 
                if p_x > 0: 
                    entropy += - p_x*math.log(p_x, 2) 
        return entropy
    except:
        return "Error"

class YaraClass:
    """Walks rule dir, compiling and testing rules, and scans files.
    """
    def __init__(self):
        """YaraClast initialization that sets verbose, scan and yara directory
        """
        try:
            self.yara_dir = YARA_RULES_DIR
            self.verbose = False
            self.compile()
        except Exception as e:
            print ("Init Compile Exception: {}".format(e))

    def compile(self):
        """Walks rule dir, tests rules, and compiles them for scanning.
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
        """Tests rules to make sure they are valid before using them.  If verbose is set will print the invalid rules.
        """
        try:
            yara.compile(filepath=test_case)
            return True
        except:
            if self.verbose:
                print ("{} is an invalid rule".format(test_case))
            return False


    def scan(self, scan_file):
        """Scan method that uses compiled rules to scan a file
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
  
    print(get_entropy(virus))

    test = YaraClass()
    rules = test.compile()
    test.test_rule(rules)
    test.scan(virus)

if __name__ == "__main__":
    main()
