import subprocess

def run(user_input):
    return subprocess.run('echo ' + user_input, shell=True, check=False)
