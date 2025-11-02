from .detect import run_pipeline
from .visualize import summarize_and_plot


def main():
    alerts = run_pipeline()
    summarize_and_plot(alerts)


if __name__ == "__main__":
    main()
