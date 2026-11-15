"""Execute the actual Dockerfile pair guard against accepted/rejected source metadata."""
import pathlib,subprocess,tempfile,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
class NaiveBuildPairTest(unittest.TestCase):
    def test_exact_pairs_and_declared_fork_base(self):
        source=(ROOT/'dockerfile/naive.dockerfile').read_text()
        guard=source.split('    && case ',1)[1].split('       esac',1)[0]
        guard='case '+guard+'esac'
        guard=guard.replace('\\\n','\n')
        with tempfile.TemporaryDirectory() as directory:
            base=pathlib.Path(directory)/'CADDY_VERSION'
            guard=guard.replace('/forwardproxy/CADDY_VERSION',str(base))
            for caddy,plugin,declared,allowed in [
                ('v2.11.9','v2.11.7-naive2','v2.11.7',True),
                ('v2.11.7','v2.11.7-naive2','v2.11.7',True),
                ('v2.11.9','v2.11.7-naive2','v2.11.9',False),
                ('v2.11.9','v2.11.7-naive3','v2.11.7',False),
                ('v2.11.10','v2.11.7-naive2','v2.11.7',False),
                ('v99.0.0','v99.0.0-naive1','v99.0.0',False)]:
                base.write_text(declared+'\n')
                result=subprocess.run(['sh','-c',guard],env={'PATH':'/usr/bin:/bin','CADDY_VERSION':caddy,'FORWARDPROXY_VERSION':plugin},capture_output=True)
                self.assertEqual(result.returncode==0,allowed,(caddy,plugin,declared))
if __name__=='__main__':unittest.main()
