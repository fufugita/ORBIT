import math


def get_entropy(input_file):
    """ Retorna a Entropia de um arquivo
    """
    try:
        with open(input_file, "rb") as arquivo:
            data = arquivo.read()
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


arch = 'inserir nome do arquivo'

entropia = get_entropy(arch)
print(entropia)
