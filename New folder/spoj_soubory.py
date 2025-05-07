import glob

output_filename = 'vysledek.txt'
files = glob.glob('*.c') + glob.glob('*.h')

with open(output_filename, 'w', encoding='utf-8') as outfile:
    for filename in files:
        outfile.write(f'{filename}\n')
        with open(filename, 'r', encoding='utf-8') as infile:
            outfile.write(infile.read())
        outfile.write('\n\n')  # dva prázdné řádky

print(f'Soubory byly spojeny do {output_filename}')