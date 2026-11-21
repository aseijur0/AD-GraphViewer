# AD-GraphViewer

AD-GraphViewer is a database-free, browser-only viewer for SharpHound and
AzureHound JSON/ZIP collections. All collection data remains in memory in the
current browser tab.
No dependencies need to be installed.

## Why
Let me preface this by saying, BloodHound is an amazing tool and I'm not trying to "create" a replacement.  

BloodHound installation and troubleshooting was a bit bothersome for me, especially when I was practicing on labs for my OSCP exam. 
After talking to my colleagues, I realized that they faced similar problems and that's what led to this tool being developed.
I wanted a lightweight BloodHound like tool that could run anywhere.


## Run

Open `index.html` directly in a modern browser. The application uses classic,
ordered browser scripts, so a local web server and build step are not required.

## Changes To Be Done

Currently, the tool just support files less than 512MB.
Another version is in progress, it'll be added under a new name depending on the requirement.

## Credits

- Luke Arndt ( for initial ideation and testing ) 
- King Remy ( for UI design and application flow )
- David Sunley ( for continuous testing and feedback ) 
- Codex, Claude - Coding
