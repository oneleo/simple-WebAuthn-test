import { useState } from "react";
import { createWebAuthn, requestWebAuthn } from "@/webAuthn";
import reactLogo from "@/assets/react.svg";
import viteLogo from "/vite.svg";
import "@/App.css";
import type { BytesLike, B64UrlString } from "@/util/typing";
import { Bytes } from "@/util/bytes";
import json from "@/util/json";

function App() {
  const [count, setCount] = useState(0);
  const [credentialId, setCredentialId] = useState<B64UrlString>("");

  const registrationWebAuthn = async () => {
    const registrationResponse = await createWebAuthn();
    setCredentialId(registrationResponse.credentialId);

    console.log(
      `[ttt] registrationResponse: ${json.stringify(
        registrationResponse,
        null,
        2
      )}`
    );
  };

  const authenticationWebAuthn = async () => {
    const challenge: BytesLike = "0x123456";
    const challengeB64Url = Bytes.wrap(challenge).unwrap("base64url");
    const authenticationResponse = await requestWebAuthn({
      credentialId,
      challenge: challengeB64Url,
    });

    console.log(
      `[ttt] authenticationResponse: ${json.stringify(
        authenticationResponse,
        null,
        2
      )}`
    );
  };

  return (
    <>
      <div>
        <a href="https://vitejs.dev" target="_blank">
          <img src={viteLogo} className="logo" alt="Vite logo" />
        </a>
        <a href="https://react.dev" target="_blank">
          <img src={reactLogo} className="logo react" alt="React logo" />
        </a>
      </div>
      <h1>Vite + React</h1>
      <div className="card">
        <button onClick={() => setCount((count) => count + 1)}>
          count is {count}
        </button>
        <p>
          Edit <code>src/App.tsx</code> and save to test HMR
        </p>
      </div>
      <div className="card">
        <button onClick={registrationWebAuthn}>WebAuthn Registration</button>
        <button onClick={authenticationWebAuthn}>
          WebAuthn Authentication
        </button>
      </div>
      <p className="read-the-docs">
        Click on the Vite and React logos to learn more
      </p>
    </>
  );
}

export default App;
