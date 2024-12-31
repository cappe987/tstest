
from matplotlib.backends.backend_pdf import PdfPages
from matplotlib.font_manager import FontProperties
import matplotlib.pyplot as plt
import numpy as np

def make_page(info, t, s):
    AX_GRAPH = 0
    AX_TABLE = 1
    fig, ax = plt.subplots(2, height_ratios=[2, 1])
    ax[AX_GRAPH].margins(0, 0)
    ax[AX_GRAPH].plot(t, s, color=info['color']) #, label="Time Error")
    # ax[0].legend()

    ax[AX_GRAPH].set(xlabel='Elapsed Time [s]', ylabel=info['ylabel'],
        title=info['title'])
    ax[AX_GRAPH].title.set_size(20)
    ax[AX_GRAPH].title.set_weight('bold')
    ax[AX_GRAPH].grid()

    # Table
    rows = ['Mean', 'Max', 'Min', 'Max-Min', 'Std. dev.', 'Messages']
    table_vals = [
        [f"{np.mean(s):.2f} ns"],
        [f"{np.max(s):.2f} ns"],
        [f"{np.min(s):.2f} ns"],
        [f"{np.max(s) - np.min(s):.2f} ns"],
        [f"{np.std(s):.2f} ns"],
        [f"{np.size(s)}"]]
    rows_bold = list(map(lambda s: "$\\bf{" + s + "}$", rows))
    table = ax[AX_TABLE].table(cellText=table_vals,
                        colWidths=[.3] * 4,
                        rowLabels=rows_bold,
                        loc='upper center')
    table.scale(1.5, 1)
    table.set_fontsize(10)
    # Set cell height
    for r in range(0, len(table_vals)):
        for c in range(-1, len(table_vals[0])):
            cell = table[r, c]
            cell.set_height(0.1)
    ax[AX_TABLE].axis("off")
    return fig



texts = {
    'TIMEERROR': {'title': 'Time Error (one-way)', 'ylabel': 'Time Error [ns]', 'color': 'blue'},
    'LATENCY': {'title': 'Latency', 'ylabel': 'Latency [ns]', 'color': 'green'},
    'PDV': {'title': 'Packet Delay Variance (PDV)', 'ylabel': 'PDV [ns]', 'color': 'red'},
}


data = open('measurements.dat', 'r').read().split('\n\n')

# print(data)

pdf = PdfPages("output.pdf")
for x in data:
    lines = x.split('\n')
    measure = lines[0].strip()
    measure_data =  [a.split() for a in lines[1:] if a != '']
    # print(measure)
    arr = np.array(measure_data, dtype=np.float32)
    time=arr[:, 0]
    values=arr[:, 1]
    fig = make_page(texts[measure], time, values)
    fig.set_size_inches(8.5, 11)
    fig.savefig(pdf, format='pdf')

pdf.close()
# plt.show()
