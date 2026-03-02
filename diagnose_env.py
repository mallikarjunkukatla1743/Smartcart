import os
def check_env():
    print("--- PythonAnywhere Env Diagnostic ---")
    base_dir = os.path.abspath(os.path.dirname(__file__))
    env_path = os.path.join(base_dir, ".env")
    
    print(f"DEBUG: Looking for .env at: {env_path}")
    if os.path.exists(env_path):
        print("SUCCESS: .env file found!")
        with open(env_path, 'r') as f:
            lines = f.readlines()
            print(f"INFO: .env has {len(lines)} lines.")
            for line in lines:
                if '=' in line and not line.startswith('#'):
                    key = line.split('=')[0]
                    print(f"  - Found Key: {key}")
    else:
        print("ERROR: .env file NOT FOUND on the server!")
        print(f"Directory contents: {os.listdir(base_dir)}")

if __name__ == "__main__":
    check_env()
