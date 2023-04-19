import {useState} from "react";
import {invoke} from "@tauri-apps/api/tauri";
import "./App.css";
import {open} from "@tauri-apps/api/dialog";
import {listen} from '@tauri-apps/api/event'

function App() {
    const [inpath, setInpath] = useState("");
    const [outpath, setOutpath] = useState("");
    const [password, setPassword] = useState("");
    const [statusOk, setStatusOk] = useState("Ready");
    const [statusErr, setStatusErr] = useState("");

    listen('tauri://file-drop', (event: any) => {
        console.log(event)
        setInpath(event.payload[0]);
        setOutpath("");
    }).then();

    const selectDir = async () => {
        const selected = await open({
            multiple: false,
            directory: true
        }) as string;

        setOutpath(selected);

        console.log("selected: ", selected);
    };

    const clear = async () => {
        setStatusErr("");
        setInpath("");
        setPassword("");
        setOutpath("");
        setStatusOk("Ready");
    };

    const start = async () => {
        await invoke("start", {inpath, outpath, password})
            .then((message: any) => {
                setStatusErr("");
                setStatusOk(message);
                console.log("message: ", message);
            })
            .catch((error: string) => {
                setStatusOk("");
                setStatusErr(error);
            });
    }

    return (
        <div className="container">
            <div className="row">
                <a href="https://tauri.app" target="_blank">
                    <img src="/tauri.svg" className="logo tauri" alt="Tauri logo"/>
                </a>
            </div>
            <div>
                <div className="helper">Drop a file or a folder into app's window</div>
                <div className="row">
                    <input
                        id="inpath"
                        disabled={true}
                        value={inpath}
                        onChange={(e) => setPassword(e.currentTarget.value)}
                        style={{marginRight: 10, width: "100%"}}
                    />
                    <button onClick={clear} style={{width: "90px"}}>Clear</button>
                </div>
                <div className="helper">Password:</div>
                <div className="row">
                    <input
                        id="password-input"
                        value={password}
                        onChange={(e) => setPassword(e.currentTarget.value)}
                        placeholder="Enter a password..."
                        style={{width: "100%", backgroundColor: "#0f0f0f"}}
                    />
                </div>
                <div className="helper">Save output file to this folder:</div>
                <div className="row">
                    <input
                        id="outpath"
                        disabled={true}
                        value={outpath}
                        onChange={(e) => setPassword(e.currentTarget.value)}
                        style={{marginRight: 10, width: "100%"}}
                    />
                    <button onClick={selectDir} style={{width: "90px"}}>Select</button>
                </div>
                <hr className="solid"/>
                <div className="row">
                    <form
                        onSubmit={(e) => {
                            e.preventDefault();
                            start().then();
                        }}
                    >
                        <button type="submit" style={{width: "350px"}}>Start</button>
                    </form>
                </div>
                <div className="helper" style={{color: "darkseagreen"}}> {statusOk} </div>
                <div className="helper" style={{color: "#C41E3A"}}> {statusErr} </div>
            </div>
        </div>
    );
}

export default App;