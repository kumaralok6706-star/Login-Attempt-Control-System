import time
import logging

logging.basicConfig(
    filename="lockout_audit.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 15 * 60

attempts = {}

def is_locked(key):
    record = attempts.get(key)
    if record and record["locked_until"]:
        if time.time() < record["locked_until"]:
            remaining = int(record["locked_until"] - time.time())
            print(f"Account/IP '{key}' is locked. Try again in {remaining} seconds.")
            return True
        else:
            attempts[key] = {"fails": 0, "locked_until": None}
    return False

def record_failure(key):
    record = attempts.setdefault(key, {"fails": 0, "locked_until": None})
    record["fails"] += 1
    print(f"Failed login for '{key}'. Attempt {record['fails']}/{MAX_ATTEMPTS}.")

    if record["fails"] >= MAX_ATTEMPTS:
        record["locked_until"] = time.time() + LOCKOUT_SECONDS
        logging.info(f"LOCKOUT triggered for '{key}' after {record['fails']} failed attempts.")
        print(f"Account/IP '{key}' locked for {LOCKOUT_SECONDS // 60} minutes.")

def record_success(key):
    attempts[key] = {"fails": 0, "locked_until": None}
    print(f"Login successful for '{key}'. Counter reset.")

def login(key, password, correct_password="secret123"):
    if is_locked(key):
        return False

    if password == correct_password:
        record_success(key)
        return True
    else:
        record_failure(key)
        return False


if __name__ == "__main__":
    test_key = "user1"
    print("=== Simulating brute-force attack ===")
    for i in range(7):
        login(test_key, "wrongpass")
        time.sleep(0.5)

    print("\n=== Trying correct password while locked ===")
    login(test_key, "secret123")
