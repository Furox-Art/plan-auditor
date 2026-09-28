# plan-auditor  
  
[![plan-audit gate](https://github.com/Furox-Art/plan-auditor/actions/workflows/plan-audit.yml/badge.svg)](https://github.com/Furox-Art/plan-auditor/actions/workflows/plan-audit.yml)  
[![PyPI](https://img.shields.io/pypi/v/plan-auditor)](https://pypi.org/project/plan-auditor/)  
[![npm](https://img.shields.io/npm/v/plan-auditor)](https://www.npmjs.com/package/plan-auditor)  
[![Downloads](https://img.shields.io/pypi/dm/plan-auditor)](https://pypi.org/project/plan-auditor/)  
![License](https://img.shields.io/badge/license-MIT-blue)  
  
I built this because I got tired of AI saying "done" when it wasn't.  
  
You know the drill: you ask an AI coding assistant to build something, it says "all tests pass," and then you find out it never actually ran them. Or it ran them once, failed, and "fixed" the test to make it green.  
  
plan-auditor forces the AI to prove its work. Not with words-with actual command output, file hashes, and deterministic checks that can't be faked.  
  
## How it works  
  
1. You describe what you want built  
2. plan-auditor turns that into explicit, machine-checkable requirements  
3. The AI implements each step and must provide real evidence (command output, file contents, test results)  
4. A separate auditor process verifies everything independently  
5. Only when every check passes does it say "done"  
  
No more "trust me bro" from language models.  
  
## Quick start  
  
```bash  
pip install plan-auditor  
# or  
npx plan-auditor  
```  
  
Then just tell your AI: "Use plan-auditor for this task." It handles the rest.  
  
## Why I made this  
  
I was working on a scientific computing project and an AI assistant kept insisting it had fixed a bug. It hadn't. Three times. I wasted hours before I realized the "fix" was just the AI editing its own test output.  
  
So I built a system where the AI can't lie. Where "done" means "here's the terminal output proving it." Where the plan is sealed cryptographically and any tampering breaks the verification.  
  
It's not perfect. But it's a hell of a lot better than taking an LLM's word for anything.  
  
## Docs  
  
- [Architecture](docs/architecture.md) - how the pieces fit together  
- [Formal Planning](docs/formal-planning.md) - the STRIPS/PDDL verification stuff  
- [Threat Model](docs/threat-model.md) - what it can and can't protect against  
  
## License  
  
MIT. Do whatever you want with it. 
