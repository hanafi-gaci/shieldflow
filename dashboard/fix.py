content = open('index.html').read()
start = content.find('<html')
end = content.rfind('</html>') + 7
open('index.html', 'w').write(content[start:end])
print('OK:', len(content[start:end]), 'chars')
