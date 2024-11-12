# Advanced Networking Lab: Kerberos

## Purpose:
Kerberos is a powerful authentication and authorization protocol that uses a key distribution center (KDC). Many infrastructures depend on Kerberos as their system's security backbone. Many more use protocols that are very similar to kerberos. Because of the protocol's prevalence in cybersecurity, this lab has been designed to help students understand the building blocks that make it work.

## Learning Outcomes
Students should learn:
- Why Kerberos is used
- How the three server infrastructure operates
- The ticketing system
- Security issues with certain Kerberos implementations

## Expected Time
3-4 hours over the course of 9 days

## Instructions
1. Research Kerberos and answer the following questions first:
    1. How does Kerberos defend against "man-in-the-middle" attacks, and what role does mutual authentication play in these defenses?
    2. How does Kerberos prevent "replay attacks," and what mechanisms does it use to secure ticket transmissions over the network?
    3. What form of encryption is most common in modern Kerberos implementations? Is this algorithm symmetric or assymetric?
    4. How can Kerberos tickets be intercepted, and what are best practices to mitigate this risk?
    5. What measures can be taken to ensure that the Kerberos Key Distribution Center (KDC) is secure, given that it is a single point of failure?
    6. How does time synchronization impact Kerberos authentication, and what risks might arise if clocks are not synchronized?
    7. What is the Kerberos "Golden Ticket" attack, and how can an organization protect itself against this type of attack?
    8. Why is Microsoft's implementation of Kerberos heavily flawed?

2. Finish the python code by following the general steps outlined in the TODO's. This python implementation of Kerberos is very simple and putting it together should help you really understand the different phases of the protocol. I'd highly reccomend using the following resource when writing the code.
![My Local Image](/images/guide.png)
The code up to and including the authentication server is provided for you.
For reference, an authenticator, not to be confused with the authentication server, is any message in Kerberos that is encrypted AND not a ticket. This shouldn't be necessary to complete the code, but many videos talk about this, and it can be confusing.
Additionally, the encyption and decryption functions have been abstracted away. This will make your job much easier.
Finally, type hinting is used to lead students in the right direction. Models of these classes have been written for you to use.

3. Once you have finished the code:
    1. Request the ```Minecraft``` service as ```Advanced_Networking_Student0``` and take a screenshot of the result
    2. Request the ```Star Wars: The Clone Wars``` service as ```Advanced_Networking_Student2``` and take a screenshot of the result
    3. Request the any service as ```Uninvited_Guest``` and take a screenshot of the result

4. Instead of taking a screenshot, request ```ms_paint``` as ```Advanced_Networking_Student0```, and observe the result. Answer the following questions:
    1. What are the advantages of having logically distinct components in authentication and authorization?
    2. How can it be inconvenient, especially if two components became misaligned?

## Deliverables
1. Answers to the eight initial questions
2. The completed python code.
3. The three screenshots of the desired outputs
4. Answers to the two follow up questions

## Resources
- See /images/guide.png
- [Kerberos Authentication Explained | A deep dive (YouTube)](https://www.youtube.com/watch?v=5N242XcKAsM)
- https://en.wikipedia.org/wiki/Kerberos_(protocol)

## Rubric
```
- 40 points total for satisfactory answers to each initial question (5 points each)
- 40 points for working kerberos implementation in python
- 10 points for all three screenshots
- 10 points total for satisfactory answers to each follow-up question (5 points each)
```