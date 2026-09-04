
# ML-KEM-Based Quantum-Resilient Checkpoint File Transfer Protocol

## Abstract

This project presents a prototype implementation of a **quantum‑resilient checkpoint file transfer protocol** tailored for **6G networks**. The protocol integrates ML‑KEM (Kyber) for post‑quantum key establishment, AES‑256‑GCM for secure encryption, and HMAC‑protected rolling checkpoints to enable efficient recovery from network disruptions. By combining post‑quantum cryptography with checkpoint‑based fault tolerance, the system ensures that interrupted transfers resume from the last verified checkpoint, avoiding redundant retransmission. Analytical modeling and simulation validate the protocol’s performance under latency, packet loss, and disruption scenarios, while a Qiskit demonstration highlights the resilience of ML‑KEM against quantum adversaries. The project contributes to ongoing research in secure and reliable 6G communication frameworks, offering both theoretical analysis and a working end‑to‑end implementation.

---

## Key Features

- **ML‑KEM (Kyber):** Post‑quantum secure key establishment  
- **AES‑256‑GCM:** Strong encryption with authentication  
- **Checkpoint Recovery:** Resume transfers from last successful checkpoint  
- **6G Network Simulation:** Models latency, packet loss, and interruptions  
- **Fault Tolerance:** Maintains reliability in unstable conditions  

---

## Technologies

- Python  
- ML‑KEM (Kyber)  
- AES‑256‑GCM  
- Post‑Quantum Cryptography  
- Qiskit (quantum demo)  
- 6G Network Simulation  

---

## Objective

To design and validate a secure, quantum‑resilient, and disruption‑tolerant file transfer mechanism for 6G networks, capable of handling interruptions efficiently while maintaining strong cryptographic guarantees against quantum adversaries.

---

## Project Members

- **Fathima Fahmiya S** (Fahmiya006)  
- **Tharun P** (Chippiiiiiii)  
- **Nivriti Muthuvairavan** (niv-csc)  
- **Mounika K M** (mounika110907)  

Developed collaboratively as part of the Department of Computer Technology, Madras Institute of Technology, Anna University.

---

## Academic Context

This work explores the intersection of **post‑quantum cryptography** and **6G network reliability**. It demonstrates:  
- Validation of ML‑KEM parameters against FIPS 203 standards  
- Analytical and simulated performance results with reproducible figures  
- A live simulator confirming theoretical predictions  
- A quantum circuit demo contrasting Shor’s algorithm with ML‑KEM resilience  

---

⭐ If you find this project relevant to your research or coursework, please consider starring the repository and citing it in your work.  

