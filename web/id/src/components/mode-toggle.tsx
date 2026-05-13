import { Moon, Sun, Laptop } from "lucide-react"
import { Button } from "@/components/ui/button"
import { useTheme } from "@/components/theme-provider"

export function ModeToggle() {
    const { theme, setTheme } = useTheme()

    const cycleTheme = () => {
        if (theme === "light") setTheme("dark")
        else if (theme === "dark") setTheme("system")
        else setTheme("light")
    }

    return (
        <Button
            variant="ghost"
            size="icon"
            onClick={cycleTheme}
            title={`Current theme: ${theme}. Click to change.`}
        >
            {/* Simplify: Just render based on state for 3-way toggle to avoid complex css collisions without tailored classes */}
            {theme === 'light' && <Sun className="h-[1.2rem] w-[1.2rem]" />}
            {theme === 'dark' && <Moon className="h-[1.2rem] w-[1.2rem]" />}
            {theme === 'system' && <Laptop className="h-[1.2rem] w-[1.2rem]" />}
            <span className="sr-only">Toggle theme</span>
        </Button>
    )
}
