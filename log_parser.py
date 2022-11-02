with open('log') as f:
    lines=f.readlines() 

with open('log.csv','w') as f:
    f.write('name,keygen,sign,verify,signature,pk,sk\n')
    for i in range(len(lines)):
        l=lines[i]
        tokens=l.split()
        if 'variant' in tokens:
            name=tokens[2]
        if 'Generating' in tokens:
            print(tokens)
            keygen=tokens[7].replace(',','')
        if 'Creating' in tokens:
            sign=lines[i+1].split()[2]
        if 'Verifying' in tokens:
            verify=lines[i+1].split()[2]
        if 'Signature' in tokens:
            signature=tokens[2].replace(',','')
        if 'Public' in tokens:
            pk=tokens[3].replace(',','')
        if 'Secret' in tokens:
            sk=tokens[3].replace(',','')
            f.write('{},{},{},{},{},{},{}\n'.format(name,keygen,sign,verify,signature,pk,sk))
