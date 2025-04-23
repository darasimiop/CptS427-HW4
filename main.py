import hashlib
from datetime import datetime

def md5_hash(password, salt):
    """Return MD5 hash of password + salt"""
    return hashlib.md5((password + salt).encode('utf-8')).hexdigest()

def load_wordlist(filepath):
    """Load word list from a file"""
    with open(filepath, 'r') as f:
        return [line.strip() for line in f if line.strip()]

def load_password_file(filepath):
    """Parse password file into list of dictionaries"""
    users = []
    with open(filepath, 'r') as f:
        for line in f:
            fields = line.strip().split(',')
            if len(fields) == 7:
                users.append({
                    "user_id": fields[0],
                    "group_id": fields[1],
                    "username": fields[2],
                    "email": fields[3],
                    "password_hash": fields[4],
                    "last_auth_date": fields[5],
                    "failed_logins": int(fields[6])
                })
    return users

def find_password_and_salt(target_hash, wordlist):
    """Brute-force match password+salt to target hash"""
    for password in wordlist:
        for salt in wordlist:
            guess_hash = md5_hash(password, salt)
            if guess_hash == target_hash:
                return password, salt
    return None, None

def main():
    wordlist = load_wordlist("wordList.txt")
    users = load_password_file("password.txt")

    # Q2: User with most failed logins
    most_failed = max(users, key=lambda u: u["failed_logins"])
    print(f"[!] Most failed logins: {most_failed['username']} with {most_failed['failed_logins']} failed attempts")

    # Q3: User who hasn't logged in for the longest time
    oldest = min(users, key=lambda u: datetime.strptime(u["last_auth_date"], "%Y%m%dT%H%M%SZ"))
    print(f"[!] Oldest last login: {oldest['username']} on {oldest['last_auth_date']}")

    print("\n[*] Cracking passwords...\n")

    for user in users:
        password, salt = find_password_and_salt(user["password_hash"], wordlist)
        if password:
            print(f"[FOUND] {user['username']} | Password: {password} | Salt: {salt}")
        else:
            print(f"[NOT FOUND] {user['username']} | Hash: {user['password_hash']}")

if __name__ == "__main__":
    main()
