"""Bound process time and pipe memory independently of the parser's behavior."""
import subprocess
import threading


def run_bounded(command, data, timeout=15, env=None, output_limit=1024*1024):
    try:
        process=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            env=env,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    except OSError as exc:
        raise ValueError('The local worker could not be started.') from exc
    output=bytearray(); exceeded=threading.Event()
    def read(stream,limit,save=False):
        count=0
        try:
            while True:
                chunk=stream.read(8192)
                if not chunk:
                    break
                count+=len(chunk)
                if count>limit:
                    exceeded.set()
                    process.kill()
                    break
                if save:
                    output.extend(chunk)
        finally:
            stream.close()
    def write():
        try:
            process.stdin.write(data)
        except (BrokenPipeError,OSError):
            pass
        finally:
            process.stdin.close()
    threads=[threading.Thread(target=read,args=(process.stdout,output_limit,True),daemon=True),
             threading.Thread(target=read,args=(process.stderr,64*1024),daemon=True),
             threading.Thread(target=write,daemon=True)]
    for thread in threads:
        thread.start()
    timed_out=False
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out=True
        process.kill(); process.wait(timeout=5)
    finally:
        for thread in threads:
            thread.join(timeout=2)
    if exceeded.is_set():
        raise ValueError('The parser exceeded its output limit.')
    if timed_out:
        raise ValueError('Static inspection timed out. The file was not executed.')
    if process.returncode:
        raise ValueError('The isolated worker could not inspect the file. Check the local worker setup.')
    return bytes(output)
