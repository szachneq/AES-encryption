file_path = 'message.txt'
# Open the file in binary read mode
with open(file_path, 'rb') as file:
    file_bytes = file.read()
    print(file_bytes)
    print(len(file_bytes))

# Now file_bytes contains the contents of the file as bytes