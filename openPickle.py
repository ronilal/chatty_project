import pickle
import hashlib
import secrets


def hash_password(password, salt, pepper='M'):
    password_bytes = password.encode('utf-8')
    salt_bytes = salt.encode('utf-8')
    pepper_bytes = pepper.encode('utf-8')

    hashed_password = hashlib.sha256(password_bytes + salt_bytes + pepper_bytes).hexdigest()

    return hashed_password

def generateSalt(length=16):
    return secrets.token_hex(length)

salt = generateSalt()
password = hash_password('200766',salt)

user = [password, salt, 'lalzarroni@gmail.com']
data = {
    'roni': user,
}


# File path to save the pickle file
file_path = 'data.pickle'

# Open the file in binary write mode
with open(file_path, 'wb') as f:
    # Pickle the data and write it to the file
    pickle.dump(data, f)