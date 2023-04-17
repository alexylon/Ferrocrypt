import {useState} from "react";
import {invoke} from "@tauri-apps/api/tauri";
import "./App.css";
import {open} from "@tauri-apps/api/dialog";

function App() {
    const [file, setFile] = useState("");
    const [password, setPassword] = useState("");

    const openFile = async () => {
        const selected = await open({
            multiple: false
        }) as string;

        setFile(selected);

        console.log("selected: ", selected);
    };

    const encrypt = async () => {
        await invoke("encrypt", {file, password});
    }

    return (
        <div className="container">
            <div className="row">
                <a href="https://tauri.app" target="_blank">
                    <img src="/tauri.svg" className="logo tauri" alt="Tauri logo"/>
                </a>
            </div>
            <div>
                <div className="row">
                    <input
                        id="file-name"
                        disabled={true}
                        onChange={(e) => setPassword(e.currentTarget.value)}
                        placeholder={file}
                        style={{marginRight: 7, width: "215px"}}
                    />
                    <button onClick={openFile}>Open file</button>
                </div>
                <div className="row">
                    <input
                        id="password-input"
                        onChange={(e) => setPassword(e.currentTarget.value)}
                        placeholder="Enter a password..."
                        style={{width: "380px"}}
                    />
                </div>
                <div className="row">
                    <form
                        onSubmit={(e) => {
                            e.preventDefault();
                            encrypt();
                        }}
                    >
                        <button
                            type="submit"
                            style={{width: "375px"}}
                        >Start</button>
                    </form>
                </div>
            </div>
        </div>
    );
}

export default App;
